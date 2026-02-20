/**
 * Windows Forensics Routes
 *
 * Provides forensic collection, artifact browsing, analysis, and scanning
 * endpoints for Windows minions using PowerShell scripts.
 *
 * Artifacts are stored as ZIP files at C:\Windows\Temp\forensics\ on each minion.
 *
 * @module routes/forensics-windows
 */

const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const { client: saltClient } = require('../lib/salt-client');
const logger = require('../lib/logger');
const { requireAuth } = require('../middleware/auth');
const { auditAction } = require('../middleware/audit');

const MINION_CACHE_BASE = '/var/cache/salt/master/minions';

/**
 * Get the local path for a cp.push'd Windows artifact, or null if not available.
 * cp.push on Windows maps C:\Windows\Temp\foo.zip → C/Windows/Temp/foo.zip in cache.
 */
function getLocalWinArtifactPath(minion, winZipPath) {
  const candidates = [
    // cp.push on Windows strips drive letter: C:\Windows\Temp\... → Windows/Temp/...
    winZipPath.replace(/^[A-Za-z]:\\/, '').replace(/\\/g, '/'),
    // Alternate: keep drive letter as dir: C:\Windows\... → C/Windows/...
    winZipPath.replace(/^([A-Za-z]):\\/, '$1/').replace(/\\/g, '/'),
    winZipPath.replace(/\\/g, '/'),
  ];
  for (const rel of candidates) {
    const full = path.join(MINION_CACHE_BASE, minion, 'files', rel);
    if (!path.resolve(full).startsWith(MINION_CACHE_BASE)) continue;
    try { if (fs.existsSync(full)) return full; } catch {}
  }
  return null;
}

/**
 * Promise wrapper around execFile for local unzip operations.
 */
function execLocal(cmd, args, opts = {}) {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { maxBuffer: 10 * 1024 * 1024, timeout: 60000, ...opts }, (err, stdout, stderr) => {
      if (err) return reject(err);
      resolve({ stdout, stderr });
    });
  });
}

const crypto = require('crypto');
const SALT_FILE_ROOTS = '/srv/salt';

/**
 * Run a PowerShell script on Windows targets reliably.
 * Uses a two-step approach: cp.get_file to push the script to each minion,
 * then cmd.run to execute it. This avoids Salt API issues with cmd.script
 * returning false due to fileserver caching inconsistencies.
 */
async function runWinPsScript(targets, scriptContent, { timeout = 180 } = {}) {
  const scriptName = `_wintmp_${crypto.randomBytes(8).toString('hex')}.ps1`;
  const scriptPath = path.join(SALT_FILE_ROOTS, scriptName);
  const remoteScriptPath = `C:\\Windows\\Temp\\${scriptName}`;
  try {
    fs.writeFileSync(scriptPath, scriptContent, 'utf8');
    // Force Salt Master to rescan file_roots so cp.get_file can find the new file
    try {
      await saltClient.run({ client: 'runner', fun: 'fileserver.update' });
    } catch (fsErr) {
      logger.warn('fileserver.update failed:', fsErr.message);
    }
    const tgt_type = Array.isArray(targets) ? 'list' : 'glob';
    // Step 1: Push script to minion(s) via cp.get_file
    const cpResult = await saltClient.run({
      client: 'local',
      fun: 'cp.get_file',
      tgt: targets,
      tgt_type,
      arg: [`salt://${scriptName}`, remoteScriptPath],
      saltTimeout: 60,
      timeout: 90000
    });
    // Verify file was pushed to all targets
    for (const [minion, val] of Object.entries(cpResult)) {
      if (!val || val === false) {
        logger.warn(`runWinPsScript: cp.get_file failed for ${minion}: ${JSON.stringify(val)}`);
      }
    }
    // Step 2: Execute the script on minion(s) via cmd.run
    const result = await saltClient.run({
      client: 'local',
      fun: 'cmd.run',
      tgt: targets,
      tgt_type,
      arg: [`powershell -ExecutionPolicy Bypass -File "${remoteScriptPath}"`],
      kwarg: { timeout },
      saltTimeout: timeout + 10,
      timeout: (timeout + 30) * 1000
    });
    logger.debug(`runWinPsScript: result preview: ${JSON.stringify(result).slice(0, 200)}`);
    // Step 3: Clean up remote script (best effort)
    try {
      await saltClient.run({
        client: 'local',
        fun: 'cmd.run',
        tgt: targets,
        tgt_type,
        arg: [`del "${remoteScriptPath}"`],
        kwarg: { timeout: 10 },
        saltTimeout: 15,
        timeout: 20000
      });
    } catch {}
    return result;
  } finally {
    try { fs.unlinkSync(scriptPath); } catch {}
  }
}

router.use(requireAuth);

// In-memory job tracking (same pattern as Linux forensics)
const winForensicJobs = new Map();

function generateJobId() {
  return 'w' + Date.now().toString(36) + Math.random().toString(36).substr(2, 6);
}

// ============================================================
// Collection Endpoints
// ============================================================

/**
 * POST /api/forensics-windows/collect
 * Start artifact collection on Windows targets
 */
router.post('/collect', auditAction('forensics_windows.collect'), async (req, res) => {
  const { targets, level = 'standard', timeout: reqTimeout } = req.body;

  if (!targets) {
    return res.status(400).json({ success: false, error: 'Targets required' });
  }

  const validLevels = ['quick', 'standard', 'advanced', 'comprehensive'];
  if (!validLevels.includes(level)) {
    return res.status(400).json({ success: false, error: `Invalid level. Must be one of: ${validLevels.join(', ')}` });
  }

  const timeoutMap = { quick: 60, standard: 180, advanced: 360, comprehensive: 600 };
  const timeout = reqTimeout || timeoutMap[level] || 180;

  const jobId = generateJobId();
  winForensicJobs.set(jobId, {
    id: jobId,
    status: 'running',
    level,
    targets,
    created: new Date().toISOString(),
    results: null
  });

  // Run async
  (async () => {
    try {
      const script = buildWinCollectScript(level);
      const result = await runWinPsScript(targets, script, { timeout });
      winForensicJobs.set(jobId, {
        ...winForensicJobs.get(jobId),
        status: 'completed',
        results: result
      });
      logger.info(`Windows forensics collection job ${jobId} completed (level: ${level})`);
    } catch (error) {
      winForensicJobs.set(jobId, {
        ...winForensicJobs.get(jobId),
        status: 'failed',
        error: error.message
      });
      logger.error(`Windows forensics collection job ${jobId} failed: ${error.message}`);
    }
  })();

  res.json({ success: true, job_id: jobId, message: `Windows ${level} collection started` });
});

/**
 * GET /api/forensics-windows/jobs
 * List all Windows forensic jobs
 */
router.get('/jobs', async (req, res) => {
  const jobs = Array.from(winForensicJobs.values()).sort((a, b) =>
    new Date(b.created) - new Date(a.created)
  );
  res.json({ success: true, jobs });
});

/**
 * GET /api/forensics-windows/jobs/:jobId
 * Get job status/results
 */
router.get('/jobs/:jobId', async (req, res) => {
  const job = winForensicJobs.get(req.params.jobId);
  if (!job) {
    return res.status(404).json({ success: false, error: 'Job not found' });
  }
  res.json({ success: true, job });
});

// ============================================================
// Browse Endpoints (ZIP-based)
// ============================================================

/**
 * GET /api/forensics-windows/collections
 * List all forensic ZIP collections across Windows targets
 */
router.get('/collections', async (req, res) => {
  try {
    const target = req.query.target || 'G@kernel:Windows';
    const tgt_type = req.query.target ? 'glob' : 'compound';
    const psCmd = `$d='C:\\Windows\\Temp\\forensics'; if(Test-Path $d){Get-ChildItem $d -Filter '*.zip' | Sort-Object LastWriteTime -Descending | ForEach-Object { $_.Name }}else{''}`;
    const result = await saltClient.run({
      client: 'local',
      fun: 'cmd.run',
      tgt: target,
      tgt_type,
      kwarg: { cmd: psCmd, shell: 'powershell', timeout: 60 },
      saltTimeout: 60,
      timeout: 90000
    });
    res.json({ success: true, collections: result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /api/forensics-windows/retrieve
 * Retrieve artifact ZIP to Salt master via cp.push for faster local browsing
 */
router.post('/retrieve', auditAction('forensics_windows.retrieve'), async (req, res) => {
  const { target, artifact_path } = req.body;
  if (!target || !artifact_path) {
    return res.status(400).json({ success: false, error: 'Target and artifact_path required' });
  }
  if (!artifact_path.match(/^C:\\Windows\\Temp\\forensics\\[a-zA-Z0-9_.-]+\.zip$/i)) {
    return res.status(400).json({ success: false, error: 'Invalid artifact path' });
  }
  try {
    const result = await saltClient.run({
      client: 'local',
      tgt: target,
      fun: 'cp.push',
      arg: [artifact_path],
      saltTimeout: 120,
      timeout: 150000
    });
    // cp.push returns false when file_recv is not enabled on the master
    const minionResult = result && result[target];
    if (minionResult === false || minionResult === 'false') {
      return res.json({
        success: false,
        error: 'cp.push returned false. Ensure file_recv: True is set in /etc/salt/master.d/ and restart salt-master.',
        result
      });
    }
    res.json({ success: true, result, local: true });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /api/forensics-windows/browse
 * List contents of a ZIP artifact on a Windows minion
 */
router.post('/browse', async (req, res) => {
  const { target, zip_path } = req.body;
  if (!target || !zip_path) {
    return res.status(400).json({ success: false, error: 'Target and zip_path required' });
  }

  // Validate path stays within forensics dir
  if (!zip_path.match(/^C:\\Windows\\Temp\\forensics\\[a-zA-Z0-9_.-]+\.zip$/i)) {
    return res.status(400).json({ success: false, error: 'Invalid ZIP path' });
  }

  try {
    // Check if artifact has been retrieved to master locally
    const localPath = getLocalWinArtifactPath(target, zip_path);
    if (localPath) {
      const { stdout } = await execLocal('python3', ['-c',
        'import zipfile,sys\nz=zipfile.ZipFile(sys.argv[1])\nfor n in z.namelist():print(n)\nz.close()',
        localPath]);
      const fileList = stdout.split('\n').filter(f => f.trim()).slice(0, 500);
      res.json({ success: true, files: { [target]: fileList }, local: true });
      return;
    }

    const safeZip = zip_path.replace(/'/g, "''");
    const psCmd = `Add-Type -AssemblyName System.IO.Compression.FileSystem; $z=[System.IO.Compression.ZipFile]::OpenRead('${safeZip}'); $z.Entries | ForEach-Object { $_.FullName }; $z.Dispose()`;
    const result = await saltClient.run({
      client: 'local',
      fun: 'cmd.run',
      tgt: target,
      tgt_type: 'glob',
      kwarg: { cmd: psCmd, shell: 'powershell', timeout: 120 },
      saltTimeout: 120,
      timeout: 150000
    });
    const files = {};
    for (const [minion, output] of Object.entries(result)) {
      files[minion] = typeof output === 'string'
        ? output.split('\n').map(f => f.trim()).filter(f => f)
        : [];
    }
    res.json({ success: true, files });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /api/forensics-windows/browse/file
 * Read a specific file from a ZIP artifact
 */
router.post('/browse/file', async (req, res) => {
  const { target, zip_path, file_path } = req.body;
  if (!target || !zip_path || !file_path) {
    return res.status(400).json({ success: false, error: 'Target, zip_path, and file_path required' });
  }

  if (!zip_path.match(/^C:\\Windows\\Temp\\forensics\\[a-zA-Z0-9_.-]+\.zip$/i)) {
    return res.status(400).json({ success: false, error: 'Invalid ZIP path' });
  }

  try {
    // Check if artifact has been retrieved to master locally
    const localPath = getLocalWinArtifactPath(target, zip_path);
    if (localPath) {
      const { stdout } = await execLocal('python3', ['-c',
        'import zipfile,sys\nz=zipfile.ZipFile(sys.argv[1])\nd=z.read(sys.argv[2]).decode("utf-8",errors="replace")\nlines=d.split("\\n")[:2000]\nprint("\\n".join(lines),end="")\nz.close()',
        localPath, file_path]);
      const truncated = stdout;
      res.json({ success: true, content: { [target]: truncated }, local: true });
      return;
    }

    // Escape single quotes in file_path for PowerShell
    const safeFilePath = file_path.replace(/'/g, "''");
    const safeZip = zip_path.replace(/'/g, "''");
    const psCmd = `Add-Type -AssemblyName System.IO.Compression.FileSystem; $z=[System.IO.Compression.ZipFile]::OpenRead('${safeZip}'); $e=$z.Entries | Where-Object { $_.FullName -eq '${safeFilePath}' } | Select-Object -First 1; if($e){ $r=New-Object System.IO.StreamReader($e.Open()); $r.ReadToEnd() -split '\\n' | Select-Object -First 2000 | ForEach-Object { $_ }; $r.Close() }else{ 'File not found in archive' }; $z.Dispose()`;
    const result = await saltClient.run({
      client: 'local',
      fun: 'cmd.run',
      tgt: target,
      tgt_type: 'glob',
      kwarg: { cmd: psCmd, shell: 'powershell', timeout: 120 },
      saltTimeout: 120,
      timeout: 150000
    });
    res.json({ success: true, content: result });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /api/forensics-windows/timeline
 * Extract file timeline data from a Windows forensics ZIP artifact.
 * Tries timeline/file_timeline.csv first, falls back to system/recent_files_*.csv,
 * then to a live PowerShell query if no collection data is available.
 */
router.post('/timeline', async (req, res) => {
  const { target, zip_path, limit = 100 } = req.body;
  if (!target) {
    return res.status(400).json({ success: false, error: 'Target required' });
  }

  const maxEntries = Math.min(Math.max(parseInt(limit) || 100, 10), 1000);

  // Helper: parse CSV text (handles quoted fields with commas)
  function parseCSVLine(line) {
    const fields = [];
    let current = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
      if (inQuotes) {
        if (line[i] === '"' && line[i + 1] === '"') {
          current += '"';
          i++;
        } else if (line[i] === '"') {
          inQuotes = false;
        } else {
          current += line[i];
        }
      } else if (line[i] === '"') {
        inQuotes = true;
      } else if (line[i] === ',') {
        fields.push(current);
        current = '';
      } else {
        current += line[i];
      }
    }
    fields.push(current);
    return fields;
  }

  function parseCSV(text) {
    const lines = text.split('\n').filter(l => l.trim());
    if (lines.length < 2) return [];
    const headers = parseCSVLine(lines[0]).map(h => h.trim().replace(/^\uFEFF/, ''));
    const rows = [];
    for (let i = 1; i < lines.length; i++) {
      const fields = parseCSVLine(lines[i]);
      const row = {};
      headers.forEach((h, idx) => { row[h] = (fields[idx] || '').trim(); });
      rows.push(row);
    }
    return rows;
  }

  function normalizeEntries(rows, source) {
    return rows.map(r => {
      if (source === 'file_timeline') {
        // Columns: Timestamp, Size, Owner, FullName
        return {
          time: r.Timestamp || r.timestamp || '',
          path: r.FullName || r.fullname || r.Path || '',
          size: r.Size || r.size || '',
          owner: r.Owner || r.owner || ''
        };
      } else {
        // recent_files CSV: FullName, LastWriteTime, Length, Extension
        return {
          time: r.LastWriteTime || r.lastwritetime || '',
          path: r.FullName || r.fullname || r.Name || '',
          size: r.Length || r.length || '',
          owner: ''
        };
      }
    }).filter(e => e.path);
  }

  // Try reading from ZIP collection
  if (zip_path && zip_path.match(/^C:\\Windows\\Temp\\forensics\\[a-zA-Z0-9_.-]+\.zip$/i)) {
    try {
      const localPath = getLocalWinArtifactPath(target, zip_path);

      // Preferred: timeline/file_timeline.csv (comprehensive level)
      const timelineFiles = ['timeline/file_timeline.csv'];
      // Fallback: system/recent_files_*.csv (standard+)
      const recentPattern = /^system\/recent_files[^/]*\.csv$/i;

      if (localPath) {
        // --- Local ZIP reading via python3 ---
        // First try to find which timeline files exist
        const { stdout: listing } = await execLocal('python3', ['-c',
          'import zipfile,sys\nz=zipfile.ZipFile(sys.argv[1])\nfor n in z.namelist():print(n)\nz.close()',
          localPath]);
        const allFiles = listing.split('\n').filter(f => f.trim());

        let csvContent = null;
        let source = '';

        // Try file_timeline.csv
        for (const tf of timelineFiles) {
          if (allFiles.some(f => f.replace(/\\/g, '/').toLowerCase() === tf.toLowerCase())) {
            const match = allFiles.find(f => f.replace(/\\/g, '/').toLowerCase() === tf.toLowerCase());
            const { stdout } = await execLocal('python3', ['-c',
              'import zipfile,sys\nz=zipfile.ZipFile(sys.argv[1])\nd=z.read(sys.argv[2]).decode("utf-8",errors="replace")\nprint(d,end="")\nz.close()',
              localPath, match]);
            csvContent = stdout;
            source = 'file_timeline';
            break;
          }
        }

        // Fallback to all recent_files CSVs (merge them)
        if (!csvContent) {
          const recentFiles = allFiles.filter(f => recentPattern.test(f.replace(/\\/g, '/')));
          if (recentFiles.length > 0) {
            let allRows = [];
            for (const rf of recentFiles) {
              const { stdout } = await execLocal('python3', ['-c',
                'import zipfile,sys\nz=zipfile.ZipFile(sys.argv[1])\nd=z.read(sys.argv[2]).decode("utf-8",errors="replace")\nprint(d,end="")\nz.close()',
                localPath, rf]);
              allRows = allRows.concat(parseCSV(stdout));
            }
            let entries = normalizeEntries(allRows, 'recent_files');
            entries.sort((a, b) => {
              const ta = new Date(a.time).getTime() || 0;
              const tb = new Date(b.time).getTime() || 0;
              return tb - ta;
            });
            entries = entries.slice(0, maxEntries);
            return res.json({ success: true, entries, source: 'collection' });
          }
        }

        if (csvContent) {
          const rows = parseCSV(csvContent);
          let entries = normalizeEntries(rows, source);
          // Sort by time descending
          entries.sort((a, b) => {
            const ta = new Date(a.time).getTime() || 0;
            const tb = new Date(b.time).getTime() || 0;
            return tb - ta;
          });
          entries = entries.slice(0, maxEntries);
          return res.json({ success: true, entries, source: 'collection' });
        }
      } else {
        // --- Remote ZIP reading via PowerShell ---
        const safeZip = zip_path.replace(/'/g, "''");

        // List entries to find timeline files
        const listCmd = `Add-Type -AssemblyName System.IO.Compression.FileSystem; $z=[System.IO.Compression.ZipFile]::OpenRead('${safeZip}'); $z.Entries | ForEach-Object { $_.FullName }; $z.Dispose()`;
        const listResult = await saltClient.run({
          client: 'local', fun: 'cmd.run', tgt: target, tgt_type: 'glob',
          kwarg: { cmd: listCmd, shell: 'powershell', timeout: 30 },
          saltTimeout: 30
        });
        const remoteFiles = (typeof listResult[target] === 'string')
          ? listResult[target].split('\n').map(f => f.trim()).filter(f => f)
          : [];

        let targetFile = null;
        let source = '';

        for (const tf of timelineFiles) {
          const match = remoteFiles.find(f => f.replace(/\\/g, '/').toLowerCase() === tf.toLowerCase());
          if (match) { targetFile = match; source = 'file_timeline'; break; }
        }
        if (!targetFile) {
          // Fallback: read all recent_files CSVs
          const recentMatches = remoteFiles.filter(f => recentPattern.test(f.replace(/\\/g, '/')));
          if (recentMatches.length > 0) {
            let allRows = [];
            for (const rf of recentMatches) {
              const safeFile = rf.replace(/'/g, "''");
              const readCmd = `Add-Type -AssemblyName System.IO.Compression.FileSystem; $z=[System.IO.Compression.ZipFile]::OpenRead('${safeZip}'); $e=$z.Entries | Where-Object { $_.FullName -eq '${safeFile}' } | Select-Object -First 1; if($e){ $r=New-Object System.IO.StreamReader($e.Open()); $r.ReadToEnd(); $r.Close() }; $z.Dispose()`;
              const readResult = await saltClient.run({
                client: 'local', fun: 'cmd.run', tgt: target, tgt_type: 'glob',
                kwarg: { cmd: readCmd, shell: 'powershell', timeout: 30 },
                saltTimeout: 30
              });
              const csv = readResult[target];
              if (typeof csv === 'string' && csv.trim()) {
                allRows = allRows.concat(parseCSV(csv));
              }
            }
            if (allRows.length > 0) {
              let entries = normalizeEntries(allRows, 'recent_files');
              entries.sort((a, b) => {
                const ta = new Date(a.time).getTime() || 0;
                const tb = new Date(b.time).getTime() || 0;
                return tb - ta;
              });
              entries = entries.slice(0, maxEntries);
              return res.json({ success: true, entries, source: 'collection' });
            }
          }
        }

        if (targetFile) {
          const safeFile = targetFile.replace(/'/g, "''");
          const readCmd = `Add-Type -AssemblyName System.IO.Compression.FileSystem; $z=[System.IO.Compression.ZipFile]::OpenRead('${safeZip}'); $e=$z.Entries | Where-Object { $_.FullName -eq '${safeFile}' } | Select-Object -First 1; if($e){ $r=New-Object System.IO.StreamReader($e.Open()); $r.ReadToEnd(); $r.Close() }; $z.Dispose()`;
          const readResult = await saltClient.run({
            client: 'local', fun: 'cmd.run', tgt: target, tgt_type: 'glob',
            kwarg: { cmd: readCmd, shell: 'powershell', timeout: 30 },
            saltTimeout: 30
          });
          const csvContent = readResult[target];
          if (typeof csvContent === 'string' && csvContent.trim()) {
            const rows = parseCSV(csvContent);
            let entries = normalizeEntries(rows, source);
            entries.sort((a, b) => {
              const ta = new Date(a.time).getTime() || 0;
              const tb = new Date(b.time).getTime() || 0;
              return tb - ta;
            });
            entries = entries.slice(0, maxEntries);
            return res.json({ success: true, entries, source: 'collection' });
          }
        }
      }
    } catch (err) {
      logger.warn(`Win forensics timeline ZIP read failed, trying live: ${err.message}`);
    }
  }

  // Live fallback: query recent files directly via PowerShell
  try {
    const psLive = `$dirs = @("$env:SystemRoot\\System32","$env:SystemRoot\\Temp","$env:TEMP","$env:ProgramData","$env:USERPROFILE");
$cutoff = (Get-Date).AddDays(-7);
$results = @();
foreach($d in $dirs){
  if(Test-Path $d){
    Get-ChildItem -Path $d -Recurse -File -ErrorAction SilentlyContinue |
      Where-Object { $_.LastWriteTime -gt $cutoff } |
      Select-Object FullName, LastWriteTime, Length, @{N='Owner';E={try{(Get-Acl $_.FullName).Owner}catch{''}}} |
      ForEach-Object { $results += $_ }
  }
}
$results | Sort-Object LastWriteTime -Descending | Select-Object -First ${maxEntries} | ConvertTo-Csv -NoTypeInformation`;

    const result = await saltClient.run({
      client: 'local', fun: 'cmd.run', tgt: target, tgt_type: 'glob',
      kwarg: { cmd: psLive, shell: 'powershell', timeout: 60 },
      saltTimeout: 60
    });

    const output = result[target];
    if (typeof output === 'string' && output.trim()) {
      const rows = parseCSV(output);
      const entries = rows.map(r => ({
        time: r.LastWriteTime || '',
        path: r.FullName || '',
        size: r.Length || '',
        owner: r.Owner || ''
      })).filter(e => e.path).slice(0, maxEntries);
      return res.json({ success: true, entries, source: 'live' });
    }

    res.json({ success: true, entries: [], source: 'none' });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================
// Analysis & Scan Endpoints
// ============================================================

/**
 * POST /api/forensics-windows/analyze
 * Run live analysis on a Windows target (examines collected artifacts)
 */
router.post('/analyze', auditAction('forensics_windows.analyze'), async (req, res) => {
  const { target, timeout = 180 } = req.body;
  if (!target) {
    return res.status(400).json({ success: false, error: 'Target required' });
  }

  try {
    const script = buildWinAnalysisScript();
    const result = await runWinPsScript(target, script, { timeout });

    const findings = {};
    for (const [minion, output] of Object.entries(result)) {
      findings[minion] = parseAnalysisOutput(output);
    }

    res.json({ success: true, findings });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

/**
 * POST /api/forensics-windows/scan
 * Quick security scan without full collection
 */
router.post('/scan', auditAction('forensics_windows.scan'), async (req, res) => {
  const { targets, deep = false, timeout: reqTimeout } = req.body;
  if (!targets) {
    return res.status(400).json({ success: false, error: 'Targets required' });
  }

  const timeout = reqTimeout || (deep ? 600 : 120);
  const scanType = deep ? 'deep_scan' : 'scan';

  const jobId = generateJobId();
  winForensicJobs.set(jobId, {
    id: jobId,
    status: 'running',
    type: scanType,
    targets,
    created: new Date().toISOString(),
    results: null
  });

  (async () => {
    try {
      const script = deep ? buildWinScanScript() : buildWinQuickScanScript();
      const result = await runWinPsScript(targets, script, { timeout });

      const findings = {};
      for (const [minion, output] of Object.entries(result)) {
        findings[minion] = parseAnalysisOutput(output);
      }

      winForensicJobs.set(jobId, {
        ...winForensicJobs.get(jobId),
        status: 'completed',
        results: result,
        findings
      });
      logger.info(`Windows forensics scan job ${jobId} completed`);
    } catch (error) {
      winForensicJobs.set(jobId, {
        ...winForensicJobs.get(jobId),
        status: 'failed',
        error: error.message
      });
      logger.error(`Windows forensics scan job ${jobId} failed: ${error.message}`);
    }
  })();

  res.json({ success: true, job_id: jobId, message: 'Windows security scan started' });
});

/**
 * POST /api/forensics-windows/cleanup
 * Clean up old forensic artifacts on Windows targets
 */
router.post('/cleanup', auditAction('forensics_windows.cleanup'), async (req, res) => {
  const { targets = '*', age_hours = 24 } = req.body;
  try {
    const psCmd = `$d='C:\\Windows\\Temp\\forensics'; if(Test-Path $d){Get-ChildItem $d -File | Where-Object { $_.LastWriteTime -lt (Get-Date).AddHours(-${age_hours}) } | Remove-Item -Force; 'Cleanup complete'}else{'No forensics directory'}`;
    const result = await saltClient.cmd(targets, psCmd, { shell: 'powershell', timeout: 60 });

    // Also clean up local cached copies from cp.push
    let localCleaned = 0;
    try {
      const minionDirs = fs.readdirSync(MINION_CACHE_BASE);
      const ageMs = age_hours * 3600 * 1000;
      const now = Date.now();
      for (const minion of minionDirs) {
        // Windows cache path: cp.push strips drive letter → Windows/Temp/forensics/
        const forensicsDir = path.join(MINION_CACHE_BASE, minion, 'files', 'Windows', 'Temp', 'forensics');
        if (!fs.existsSync(forensicsDir)) continue;
        const files = fs.readdirSync(forensicsDir);
        for (const file of files) {
          const full = path.join(forensicsDir, file);
          try {
            const stat = fs.statSync(full);
            if (stat.isFile() && (now - stat.mtimeMs) > ageMs) {
              fs.unlinkSync(full);
              localCleaned++;
            }
          } catch (fileErr) {
            logger.warn(`Local cache cleanup file error: ${full}: ${fileErr.message}`);
          }
        }
      }
    } catch (e) {
      logger.warn(`Local cache cleanup error: ${e.message}`);
    }

    res.json({ success: true, result, local_cleaned: localCleaned });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// ============================================================
// Helper: Parse Analysis Output
// ============================================================

function parseAnalysisOutput(output) {
  if (typeof output !== 'string') return [];
  const findings = [];
  let currentCategory = 'unknown';
  let currentSeverity = 'info';

  for (const line of output.split('\n')) {
    const catMatch = line.match(/\[CATEGORY:(\w+)\]/);
    if (catMatch) { currentCategory = catMatch[1]; continue; }

    const sevMatch = line.match(/\[SEVERITY:(\w+)\]/);
    if (sevMatch) { currentSeverity = sevMatch[1]; continue; }

    const findMatch = line.match(/\[FINDING\]\s*(.*)/);
    if (findMatch) {
      findings.push({
        category: currentCategory,
        severity: currentSeverity,
        message: findMatch[1],
        timestamp: new Date().toISOString()
      });
    }
  }
  return findings;
}

// ============================================================
// PowerShell Collection Scripts
// ============================================================

function buildWinCollectScript(level) {
  // Base collection that all levels include
  const base = `
$ErrorActionPreference='SilentlyContinue'
$ts=Get-Date -Format 'yyyyMMdd_HHmmss'
$hostname=$env:COMPUTERNAME
$baseDir="C:\\Windows\\Temp\\forensics"
$collectDir="$baseDir\\collect_$ts"
New-Item -ItemType Directory -Force -Path $collectDir | Out-Null
New-Item -ItemType Directory -Force -Path "$collectDir\\processes" | Out-Null
New-Item -ItemType Directory -Force -Path "$collectDir\\network" | Out-Null
New-Item -ItemType Directory -Force -Path "$collectDir\\users" | Out-Null
New-Item -ItemType Directory -Force -Path "$collectDir\\persistence" | Out-Null
New-Item -ItemType Directory -Force -Path "$collectDir\\system" | Out-Null
New-Item -ItemType Directory -Force -Path "$collectDir\\security_events" | Out-Null

# Metadata
@{
  collected_at=(Get-Date -Format 'o')
  hostname=$hostname
  level='${level}'
  os=(Get-CimInstance Win32_OperatingSystem).Caption
  os_version=(Get-CimInstance Win32_OperatingSystem).Version
  domain=(Get-CimInstance Win32_ComputerSystem).Domain
  is_dc=((Get-CimInstance Win32_OperatingSystem).ProductType -eq 2)
} | ConvertTo-Json | Out-File "$collectDir\\metadata.json" -Encoding UTF8

Write-Output "[STATUS] Collecting process information..."
# Running processes
Get-Process | Select-Object Id,ProcessName,Path,StartTime,CPU,WorkingSet64,Company,Description |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\processes\\running_processes.csv" -Encoding UTF8

# Process command lines with parent info
Get-CimInstance Win32_Process | Select-Object ProcessId,Name,CommandLine,ExecutablePath,ParentProcessId,CreationDate |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\processes\\process_cmdlines.csv" -Encoding UTF8

Write-Output "[STATUS] Collecting network information..."
# Network connections
Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,CreationTime |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\network\\tcp_connections.csv" -Encoding UTF8
Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess,CreationTime |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\network\\udp_endpoints.csv" -Encoding UTF8

# Logged-in users
query user 2>$null | Out-File "$collectDir\\users\\logged_in_users.txt" -Encoding UTF8

Write-Output "[STATUS] Collecting persistence mechanisms..."
# Scheduled tasks summary
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } |
  Select-Object TaskName,TaskPath,State,@{N='Actions';E={($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join '; '}} |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\persistence\\scheduled_tasks.csv" -Encoding UTF8

# Autorun registry keys
$autorunKeys = @(
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
  'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
)
$autoruns = foreach($key in $autorunKeys) {
  if(Test-Path $key) {
    $props = Get-ItemProperty $key
    $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
      [PSCustomObject]@{ Key=$key; Name=$_.Name; Value=$_.Value }
    }
  }
}
$autoruns | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\persistence\\autorun_registry.csv" -Encoding UTF8

# Active services
Get-Service | Select-Object Name,DisplayName,Status,StartType |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\system\\services.csv" -Encoding UTF8

Write-Output "[STATUS] Collecting targeted security events..."
# Targeted Security Event Queries (high-value, not raw dumps)

# Logon events (4624 success, 4625 failure) - last 200 each
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 200 2>$null |
  ForEach-Object {
    $xml=[xml]$_.ToXml()
    $d=$xml.Event.EventData.Data
    [PSCustomObject]@{
      TimeCreated=$_.TimeCreated; LogonType=($d | Where-Object Name -eq 'LogonType').'#text'
      TargetUser=($d | Where-Object Name -eq 'TargetUserName').'#text'
      TargetDomain=($d | Where-Object Name -eq 'TargetDomainName').'#text'
      SourceIP=($d | Where-Object Name -eq 'IpAddress').'#text'
      LogonProcess=($d | Where-Object Name -eq 'LogonProcessName').'#text'
    }
  } | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\security_events\\logon_success_4624.csv" -Encoding UTF8

Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625} -MaxEvents 200 2>$null |
  ForEach-Object {
    $xml=[xml]$_.ToXml()
    $d=$xml.Event.EventData.Data
    [PSCustomObject]@{
      TimeCreated=$_.TimeCreated; LogonType=($d | Where-Object Name -eq 'LogonType').'#text'
      TargetUser=($d | Where-Object Name -eq 'TargetUserName').'#text'
      SourceIP=($d | Where-Object Name -eq 'IpAddress').'#text'
      FailureReason=($d | Where-Object Name -eq 'FailureReason').'#text'
      Status=($d | Where-Object Name -eq 'Status').'#text'
      SubStatus=($d | Where-Object Name -eq 'SubStatus').'#text'
    }
  } | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\security_events\\logon_failure_4625.csv" -Encoding UTF8

# Process creation (4688) - last 500
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4688} -MaxEvents 500 2>$null |
  ForEach-Object {
    $xml=[xml]$_.ToXml()
    $d=$xml.Event.EventData.Data
    [PSCustomObject]@{
      TimeCreated=$_.TimeCreated
      NewProcessName=($d | Where-Object Name -eq 'NewProcessName').'#text'
      CommandLine=($d | Where-Object Name -eq 'CommandLine').'#text'
      ParentProcessName=($d | Where-Object Name -eq 'ParentProcessName').'#text'
      SubjectUserName=($d | Where-Object Name -eq 'SubjectUserName').'#text'
      TokenElevationType=($d | Where-Object Name -eq 'TokenElevationType').'#text'
    }
  } | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\security_events\\process_creation_4688.csv" -Encoding UTF8

# New service installed (7045) - all recent
Get-WinEvent -FilterHashtable @{LogName='System';Id=7045} -MaxEvents 100 2>$null |
  ForEach-Object {
    $xml=[xml]$_.ToXml()
    $d=$xml.Event.EventData.Data
    [PSCustomObject]@{
      TimeCreated=$_.TimeCreated
      ServiceName=($d | Where-Object Name -eq 'ServiceName').'#text'
      ImagePath=($d | Where-Object Name -eq 'ImagePath').'#text'
      ServiceType=($d | Where-Object Name -eq 'ServiceType').'#text'
      StartType=($d | Where-Object Name -eq 'StartType').'#text'
      AccountName=($d | Where-Object Name -eq 'AccountName').'#text'
    }
  } | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\security_events\\new_service_7045.csv" -Encoding UTF8

# Audit log cleared (1102)
Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} -MaxEvents 50 2>$null |
  Select-Object TimeCreated,Id,Message |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\security_events\\audit_cleared_1102.csv" -Encoding UTF8

# Account management events (4720 created, 4722 enabled, 4724 pw reset, 4726 deleted, 4728/4732/4756 group add)
$acctEventIds = @(4720,4722,4724,4726,4728,4732,4756)
Get-WinEvent -FilterHashtable @{LogName='Security';Id=$acctEventIds} -MaxEvents 200 2>$null |
  ForEach-Object {
    $xml=[xml]$_.ToXml()
    $d=$xml.Event.EventData.Data
    [PSCustomObject]@{
      TimeCreated=$_.TimeCreated; EventId=$_.Id
      TargetUser=($d | Where-Object Name -eq 'TargetUserName').'#text'
      SubjectUser=($d | Where-Object Name -eq 'SubjectUserName').'#text'
      MemberName=($d | Where-Object Name -eq 'MemberName').'#text'
      GroupName=($d | Where-Object Name -eq 'TargetUserName').'#text'
    }
  } | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\security_events\\account_mgmt.csv" -Encoding UTF8

Write-Output "[STATUS] Collecting Windows Defender status..."
# Windows Defender status
try {
  Get-MpComputerStatus 2>$null | Select-Object AMServiceEnabled,AntispywareEnabled,AntivirusEnabled,
    BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,OnAccessProtectionEnabled,
    RealTimeProtectionEnabled,AntivirusSignatureLastUpdated,AntivirusSignatureAge,
    FullScanAge,QuickScanAge,QuickScanStartTime,FullScanStartTime |
    ConvertTo-Json | Out-File "$collectDir\\system\\defender_status.json" -Encoding UTF8
  Get-MpThreatDetection 2>$null | Select-Object -First 50 ThreatID,ThreatName,DomainUser,ProcessName,
    InitialDetectionTime,LastThreatStatusChangeTime,RemediationTime,ActionSuccess,Resources |
    ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\system\\defender_threats.csv" -Encoding UTF8
} catch { "Defender not available" | Out-File "$collectDir\\system\\defender_status.json" -Encoding UTF8 }

# Recent Security events (last 100 raw for quick reference)
Get-WinEvent -LogName Security -MaxEvents 100 2>$null |
  Select-Object TimeCreated,Id,LevelDisplayName,Message |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\system\\eventlog_security_recent.csv" -Encoding UTF8
# Recent System events (last 100)
Get-WinEvent -LogName System -MaxEvents 100 2>$null |
  Select-Object TimeCreated,Id,LevelDisplayName,Message |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\system\\eventlog_system_recent.csv" -Encoding UTF8
`;

  const standard = `
Write-Output "[STATUS] Collecting detailed scheduled tasks..."
# Detailed scheduled task info
Get-ScheduledTask | ForEach-Object {
  $info = Get-ScheduledTaskInfo $_.TaskName -ErrorAction SilentlyContinue
  [PSCustomObject]@{
    TaskName=$_.TaskName; TaskPath=$_.TaskPath; State=$_.State
    Actions=($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join '; '
    Triggers=($_.Triggers | ForEach-Object { $_.ToString() }) -join '; '
    LastRunTime=$info.LastRunTime; NextRunTime=$info.NextRunTime
    Author=$_.Author; Principal=$_.Principal.UserId
  }
} | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\persistence\\scheduled_tasks_detail.csv" -Encoding UTF8

Write-Output "[STATUS] Checking WMI subscriptions..."
# WMI event subscriptions (common persistence)
Get-WmiObject -Namespace root\\subscription -Class __EventConsumer 2>$null |
  Select-Object __CLASS,Name,CommandLineTemplate,ScriptText |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\persistence\\wmi_consumers.csv" -Encoding UTF8
Get-WmiObject -Namespace root\\subscription -Class __EventFilter 2>$null |
  Select-Object Name,Query,QueryLanguage |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\persistence\\wmi_filters.csv" -Encoding UTF8

Write-Output "[STATUS] Collecting PowerShell history..."
# PowerShell history (all users)
$userProfiles = Get-ChildItem 'C:\\Users' -Directory -ErrorAction SilentlyContinue
foreach($profile in $userProfiles) {
  $histPath = Join-Path $profile.FullName 'AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt'
  if(Test-Path $histPath) {
    $content = Get-Content $histPath -Tail 200 -ErrorAction SilentlyContinue
    if($content) {
      "=== $($profile.Name) ===" | Out-File "$collectDir\\persistence\\powershell_history.txt" -Append -Encoding UTF8
      $content | Out-File "$collectDir\\persistence\\powershell_history.txt" -Append -Encoding UTF8
    }
  }
}

Write-Output "[STATUS] Collecting installed software..."
# Installed software
Get-ItemProperty HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*,
  HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* 2>$null |
  Where-Object { $_.DisplayName } |
  Select-Object DisplayName,DisplayVersion,Publisher,InstallDate |
  Sort-Object DisplayName |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\system\\installed_software.csv" -Encoding UTF8

# Local users and groups
Get-LocalUser | Select-Object Name,Enabled,LastLogon,PasswordLastSet,Description |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\users\\local_users.csv" -Encoding UTF8
Get-LocalGroup | ForEach-Object {
  $members = Get-LocalGroupMember $_.Name -ErrorAction SilentlyContinue
  [PSCustomObject]@{ Group=$_.Name; Members=($members.Name -join ', ') }
} | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\users\\local_groups.csv" -Encoding UTF8

Write-Output "[STATUS] Collecting firewall rules..."
# Firewall rules (enabled only)
Get-NetFirewallRule -Enabled True 2>$null |
  Select-Object DisplayName,Direction,Action,Profile |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\network\\firewall_rules.csv" -Encoding UTF8

# DNS cache
Get-DnsClientCache 2>$null |
  Select-Object Entry,RecordName,RecordType,Data,TimeToLive |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\network\\dns_cache.csv" -Encoding UTF8

Write-Output "[STATUS] Checking recent file modifications..."
# Recent file modifications in key directories
$searchDirs = @('C:\\Windows\\System32', 'C:\\Windows\\Temp', 'C:\\Users')
$cutoff = (Get-Date).AddDays(-7)
foreach($dir in $searchDirs) {
  if(Test-Path $dir) {
    Get-ChildItem $dir -Recurse -File -ErrorAction SilentlyContinue |
      Where-Object { $_.LastWriteTime -gt $cutoff } |
      Select-Object -First 200 FullName,LastWriteTime,Length,Extension |
      ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\system\\recent_files_$($dir.Replace('\\','_').Replace(':','')).csv" -Append -Encoding UTF8
  }
}

# Prefetch files listing
if(Test-Path 'C:\\Windows\\Prefetch') {
  Get-ChildItem 'C:\\Windows\\Prefetch' -Filter '*.pf' |
    Select-Object Name,LastWriteTime,Length |
    Sort-Object LastWriteTime -Descending |
    ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\system\\prefetch.csv" -Encoding UTF8
}

# Alternate Data Streams on common paths
$adsResults = @()
foreach($dir in @('C:\\Users','C:\\Windows\\Temp')) {
  if(Test-Path $dir) {
    Get-ChildItem $dir -Recurse -File -ErrorAction SilentlyContinue |
      Select-Object -First 500 |
      ForEach-Object {
        $streams = Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue |
          Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }
        foreach($s in $streams) {
          $adsResults += [PSCustomObject]@{ File=$_.FullName; Stream=$s.Stream; Length=$s.Length }
        }
      }
  }
}
if($adsResults.Count -gt 0) {
  $adsResults | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\persistence\\alternate_data_streams.csv" -Encoding UTF8
}

Write-Output "[STATUS] Collecting deep persistence mechanisms..."
# AppInit_DLLs (DLL injection persistence)
$appInitPaths = @(
  'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows',
  'HKLM:\\SOFTWARE\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows'
)
$appInitResults = @()
foreach($p in $appInitPaths) {
  if(Test-Path $p) {
    $props = Get-ItemProperty $p
    $appInitResults += [PSCustomObject]@{
      Path=$p
      AppInit_DLLs=$props.AppInit_DLLs
      LoadAppInit_DLLs=$props.LoadAppInit_DLLs
    }
  }
}
$appInitResults | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\persistence\\appinit_dlls.csv" -Encoding UTF8

# LSA Security/Authentication/Notification Packages
$lsaPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'
if(Test-Path $lsaPath) {
  $lsa = Get-ItemProperty $lsaPath
  [PSCustomObject]@{
    SecurityPackages=$lsa.'Security Packages' -join ','
    AuthenticationPackages=$lsa.'Authentication Packages' -join ','
    NotificationPackages=$lsa.'Notification Packages' -join ','
  } | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\persistence\\lsa_packages.csv" -Encoding UTF8
}

# Security Support Providers
$sspPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig'
if(Test-Path $sspPath) {
  (Get-ItemProperty $sspPath).'Security Packages' | Out-File "$collectDir\\persistence\\ssp_packages.txt" -Encoding UTF8
}

# Boot Execute entries
$bootExec = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager' -ErrorAction SilentlyContinue).BootExecute
if($bootExec) { $bootExec | Out-File "$collectDir\\persistence\\boot_execute.txt" -Encoding UTF8 }

# Print Monitor DLLs
$monPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Print\\Monitors'
if(Test-Path $monPath) {
  Get-ChildItem $monPath | ForEach-Object {
    $drv = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Driver
    [PSCustomObject]@{ Monitor=$_.PSChildName; Driver=$drv }
  } | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\persistence\\print_monitors.csv" -Encoding UTF8
}

# PowerShell profiles (all locations)
$psProfiles = @(
  "$env:WINDIR\\System32\\WindowsPowerShell\\v1.0\\profile.ps1",
  "$env:WINDIR\\System32\\WindowsPowerShell\\v1.0\\Microsoft.PowerShell_profile.ps1",
  "$env:USERPROFILE\\Documents\\WindowsPowerShell\\profile.ps1",
  "$env:USERPROFILE\\Documents\\WindowsPowerShell\\Microsoft.PowerShell_profile.ps1",
  "C:\\Program Files\\PowerShell\\7\\profile.ps1"
)
$profileResults = @()
foreach($pp in $psProfiles) {
  if(Test-Path $pp) {
    $profileResults += [PSCustomObject]@{ Path=$pp; Size=(Get-Item $pp).Length; Content=(Get-Content $pp -Raw -ErrorAction SilentlyContinue | Select-Object -First 1) }
  }
}
if($profileResults.Count -gt 0) {
  $profileResults | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\persistence\\powershell_profiles.csv" -Encoding UTF8
}

# Startup folders (all users + per-user)
$startupPaths = @(
  'C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup',
  "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
)
$startupItems = @()
foreach($sp in $startupPaths) {
  if(Test-Path $sp) {
    Get-ChildItem $sp -File -ErrorAction SilentlyContinue | ForEach-Object {
      $startupItems += [PSCustomObject]@{ Path=$sp; File=$_.Name; Size=$_.Length; LastWrite=$_.LastWriteTime }
    }
  }
}
if($startupItems.Count -gt 0) {
  $startupItems | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\persistence\\startup_folders.csv" -Encoding UTF8
}

# Unquoted service paths
Get-WmiObject Win32_Service 2>$null | Where-Object {
  $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -notmatch '^[A-Za-z]:\\Windows\\' -and $_.PathName -match ' '
} | Select-Object Name,DisplayName,PathName,StartMode,State |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\persistence\\unquoted_service_paths.csv" -Encoding UTF8

Write-Output "[STATUS] Collecting deep event log analysis..."
# PowerShell Script Block Logging (4104) - see actual commands attackers ran
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational';Id=4104} -MaxEvents 200 2>$null |
  ForEach-Object {
    $xml=[xml]$_.ToXml()
    $d=$xml.Event.EventData.Data
    [PSCustomObject]@{
      TimeCreated=$_.TimeCreated
      ScriptBlockText=($d | Where-Object Name -eq 'ScriptBlockText').'#text'
      Path=($d | Where-Object Name -eq 'Path').'#text'
    }
  } | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\security_events\\powershell_scriptblock_4104.csv" -Encoding UTF8

# Explicit credential logon (4648) - pass-the-hash indicator
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4648} -MaxEvents 100 2>$null |
  ForEach-Object {
    $xml=[xml]$_.ToXml()
    $d=$xml.Event.EventData.Data
    [PSCustomObject]@{
      TimeCreated=$_.TimeCreated
      SubjectUser=($d | Where-Object Name -eq 'SubjectUserName').'#text'
      TargetUser=($d | Where-Object Name -eq 'TargetUserName').'#text'
      TargetServer=($d | Where-Object Name -eq 'TargetServerName').'#text'
      ProcessName=($d | Where-Object Name -eq 'ProcessName').'#text'
    }
  } | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\security_events\\explicit_cred_4648.csv" -Encoding UTF8

# Special privileges assigned (4672)
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4672} -MaxEvents 100 2>$null |
  ForEach-Object {
    $xml=[xml]$_.ToXml()
    $d=$xml.Event.EventData.Data
    [PSCustomObject]@{
      TimeCreated=$_.TimeCreated
      SubjectUser=($d | Where-Object Name -eq 'SubjectUserName').'#text'
      PrivilegeList=($d | Where-Object Name -eq 'PrivilegeList').'#text'
    }
  } | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\security_events\\special_privs_4672.csv" -Encoding UTF8

# Windows Defender events (1116 detection, 1117 action, 5001 RT protection disabled)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';Id=@(1116,1117,5001)} -MaxEvents 100 2>$null |
  Select-Object TimeCreated,Id,LevelDisplayName,Message |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\security_events\\defender_events.csv" -Encoding UTF8

# RDP connection events (from TerminalServices-LocalSessionManager)
Get-WinEvent -LogName 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational' -MaxEvents 100 2>$null |
  Select-Object TimeCreated,Id,Message |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\security_events\\rdp_sessions.csv" -Encoding UTF8

# Service start type changes (7040)
Get-WinEvent -FilterHashtable @{LogName='System';Id=7040} -MaxEvents 100 2>$null |
  Select-Object TimeCreated,Id,Message |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\security_events\\service_changes_7040.csv" -Encoding UTF8

Write-Output "[STATUS] Collecting SMB and network details..."
# SMB shares, sessions, open files
Get-SmbShare 2>$null | Select-Object Name,Path,Description,CurrentUsers |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\network\\smb_shares.csv" -Encoding UTF8
Get-SmbSession 2>$null | Select-Object ClientComputerName,ClientUserName,NumOpens,SecondsExists |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\network\\smb_sessions.csv" -Encoding UTF8
Get-SmbOpenFile 2>$null | Select-Object ClientComputerName,ClientUserName,Path |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\network\\smb_openfiles.csv" -Encoding UTF8

# Network profiles and proxy settings
Get-NetConnectionProfile 2>$null | Select-Object Name,InterfaceAlias,NetworkCategory,IPv4Connectivity |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\network\\network_profiles.csv" -Encoding UTF8
netsh winhttp show proxy 2>$null | Out-File "$collectDir\\network\\proxy_settings.txt" -Encoding UTF8

Write-Output "[STATUS] Collecting process and session analysis..."
# Security policy export
secedit /export /cfg "$collectDir\\system\\security_policy.inf" /quiet 2>$null

# Active logon sessions
qwinsta 2>$null | Out-File "$collectDir\\users\\active_sessions.txt" -Encoding UTF8

# Credential Manager entries
cmdkey /list 2>$null | Out-File "$collectDir\\users\\credential_manager.txt" -Encoding UTF8
`;

  const advanced = `
Write-Output "[STATUS] Exporting full event logs..."
# Full event log exports (last 1000 entries each)
foreach($logName in @('Security','System','Microsoft-Windows-PowerShell/Operational')) {
  $safeName = $logName -replace '[/\\\\]','_'
  Get-WinEvent -LogName $logName -MaxEvents 1000 2>$null |
    Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message |
    ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\system\\eventlog_\${safeName}_full.csv" -Encoding UTF8
}

Write-Output "[STATUS] Collecting registry persistence locations..."
# Extended registry persistence locations
New-Item -ItemType Directory -Force -Path "$collectDir\\persistence\\registry" | Out-Null
$persistKeys = @(
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices',
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce',
  'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
  'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows',
  'HKLM:\\SYSTEM\\CurrentControlSet\\Services',
  'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options',
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler',
  'HKLM:\\SOFTWARE\\Classes\\CLSID',
  'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
)
foreach($key in $persistKeys) {
  $safeName = ($key -replace '[:\\\\]','_') -replace '^_+',''
  if(Test-Path $key) {
    $shortName = $safeName.Substring([Math]::Max(0,$safeName.Length-80))
    Get-ItemProperty $key -ErrorAction SilentlyContinue |
      Out-File "$collectDir\\persistence\\registry\\$shortName.txt" -Encoding UTF8
  }
}

Write-Output "[STATUS] Collecting certificate store info..."
# Certificate store
Get-ChildItem Cert:\\LocalMachine\\Root |
  Select-Object Subject,Issuer,NotBefore,NotAfter,Thumbprint |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\system\\certificates_root.csv" -Encoding UTF8

Write-Output "[STATUS] Collecting driver list..."
# Drivers
Get-WindowsDriver -Online -All 2>$null |
  Select-Object OriginalFileName,ProviderName,Date,Version,ClassName |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\system\\drivers.csv" -Encoding UTF8
# Fallback if Get-WindowsDriver is not available
if(-not (Test-Path "$collectDir\\system\\drivers.csv") -or (Get-Item "$collectDir\\system\\drivers.csv").Length -lt 100) {
  driverquery /v /fo csv 2>$null | Out-File "$collectDir\\system\\drivers.csv" -Encoding UTF8
}

Write-Output "[STATUS] Collecting named pipes..."
# Named pipes
Get-ChildItem \\\\.\\pipe\\ -ErrorAction SilentlyContinue |
  Select-Object Name | Out-File "$collectDir\\system\\named_pipes.txt" -Encoding UTF8

Write-Output "[STATUS] Checking COM object hijacks..."
# COM object hijack checks (known hijack CLSIDs)
$suspectCLSIDs = @(
  '{b5f8350b-0548-48b1-a6ee-88bd00b4a5e7}',
  '{BCDE0395-E52F-467C-8E3D-C4579291692E}',
  '{C08AFD90-F2A1-11D1-8455-00A0C91F3880}'
)
$comResults = @()
foreach($clsid in $suspectCLSIDs) {
  $regPath = "HKCU:\\SOFTWARE\\Classes\\CLSID\\$clsid\\InProcServer32"
  if(Test-Path $regPath) {
    $val = (Get-ItemProperty $regPath -ErrorAction SilentlyContinue).'(default)'
    $comResults += [PSCustomObject]@{ CLSID=$clsid; Path=$val; Source='HKCU' }
  }
}
if($comResults.Count -gt 0) {
  $comResults | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\persistence\\com_hijacks.csv" -Encoding UTF8
}

Write-Output "[STATUS] Hashing critical system binaries..."
# SHA256 of critical system binaries
New-Item -ItemType Directory -Force -Path "$collectDir\\integrity" | Out-Null
$criticalBins = @(
  "$env:WINDIR\\System32\\cmd.exe",
  "$env:WINDIR\\System32\\powershell.exe",
  "$env:WINDIR\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "$env:WINDIR\\System32\\svchost.exe",
  "$env:WINDIR\\System32\\lsass.exe",
  "$env:WINDIR\\System32\\csrss.exe",
  "$env:WINDIR\\System32\\services.exe",
  "$env:WINDIR\\System32\\winlogon.exe",
  "$env:WINDIR\\System32\\wininit.exe",
  "$env:WINDIR\\System32\\smss.exe",
  "$env:WINDIR\\System32\\taskmgr.exe",
  "$env:WINDIR\\System32\\net.exe",
  "$env:WINDIR\\System32\\net1.exe",
  "$env:WINDIR\\System32\\netsh.exe",
  "$env:WINDIR\\System32\\sc.exe",
  "$env:WINDIR\\System32\\reg.exe",
  "$env:WINDIR\\System32\\wmic.exe",
  "$env:WINDIR\\System32\\mshta.exe",
  "$env:WINDIR\\System32\\regsvr32.exe",
  "$env:WINDIR\\System32\\rundll32.exe",
  "$env:WINDIR\\System32\\certutil.exe",
  "$env:WINDIR\\System32\\bitsadmin.exe",
  "$env:WINDIR\\System32\\dns.exe"
)
$criticalBins | ForEach-Object {
  if(Test-Path $_) {
    $hash = (Get-FileHash $_ -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    $sig = Get-AuthenticodeSignature $_ -ErrorAction SilentlyContinue
    [PSCustomObject]@{ Path=$_; SHA256=$hash; SignatureStatus=$sig.Status; Signer=$sig.SignerCertificate.Subject }
  }
} | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\integrity\\critical_binaries.csv" -Encoding UTF8

# Scan first 100 System32 EXEs for unsigned binaries
Get-ChildItem "$env:WINDIR\\System32\\*.exe" -ErrorAction SilentlyContinue | Select-Object -First 100 | ForEach-Object {
  $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue
  if($sig.Status -ne 'Valid') {
    [PSCustomObject]@{ Path=$_.FullName; Status=$sig.Status; Size=$_.Length; LastWrite=$_.LastWriteTime }
  }
} | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\integrity\\unsigned_system32.csv" -Encoding UTF8

Write-Output "[STATUS] Checking advanced persistence mechanisms..."
# Defender exclusions (attackers add exclusions to hide malware)
try {
  $prefs = Get-MpPreference 2>$null
  if($prefs) {
    [PSCustomObject]@{
      ExclusionPath=$prefs.ExclusionPath -join ','
      ExclusionExtension=$prefs.ExclusionExtension -join ','
      ExclusionProcess=$prefs.ExclusionProcess -join ','
    } | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\system\\defender_exclusions.csv" -Encoding UTF8
  }
} catch {}

# Sysmon events (if Sysmon is installed)
$sysmonLog = 'Microsoft-Windows-Sysmon/Operational'
$hasSysmon = Get-WinEvent -ListLog $sysmonLog -ErrorAction SilentlyContinue
if($hasSysmon) {
  New-Item -ItemType Directory -Force -Path "$collectDir\\sysmon" | Out-Null
  # Process Create (1)
  Get-WinEvent -FilterHashtable @{LogName=$sysmonLog;Id=1} -MaxEvents 500 2>$null |
    Select-Object TimeCreated,Message | ConvertTo-Csv -NoTypeInformation |
    Out-File "$collectDir\\sysmon\\process_create.csv" -Encoding UTF8
  # Network Connect (3)
  Get-WinEvent -FilterHashtable @{LogName=$sysmonLog;Id=3} -MaxEvents 200 2>$null |
    Select-Object TimeCreated,Message | ConvertTo-Csv -NoTypeInformation |
    Out-File "$collectDir\\sysmon\\network_connect.csv" -Encoding UTF8
  # File Create (11)
  Get-WinEvent -FilterHashtable @{LogName=$sysmonLog;Id=11} -MaxEvents 200 2>$null |
    Select-Object TimeCreated,Message | ConvertTo-Csv -NoTypeInformation |
    Out-File "$collectDir\\sysmon\\file_create.csv" -Encoding UTF8
  # Registry (13)
  Get-WinEvent -FilterHashtable @{LogName=$sysmonLog;Id=13} -MaxEvents 200 2>$null |
    Select-Object TimeCreated,Message | ConvertTo-Csv -NoTypeInformation |
    Out-File "$collectDir\\sysmon\\registry_value.csv" -Encoding UTF8
}

# Network/RDP logon type analysis
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624} -MaxEvents 500 2>$null | ForEach-Object {
  $xml=[xml]$_.ToXml()
  $d=$xml.Event.EventData.Data
  $lt=($d | Where-Object Name -eq 'LogonType').'#text'
  if($lt -in @('3','4','5','10')) {
    [PSCustomObject]@{
      TimeCreated=$_.TimeCreated; LogonType=$lt
      TypeName=switch($lt){'3'{'Network'}; '4'{'Batch'}; '5'{'Service'}; '10'{'RDP'}}
      User=($d | Where-Object Name -eq 'TargetUserName').'#text'
      Source=($d | Where-Object Name -eq 'IpAddress').'#text'
    }
  }
} | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\security_events\\network_rdp_logons.csv" -Encoding UTF8

Write-Output "[STATUS] Checking Active Directory (if DC)..."
# AD-specific checks (if this is a DC)
$isDC = (Get-CimInstance Win32_OperatingSystem).ProductType -eq 2
if($isDC) {
  New-Item -ItemType Directory -Force -Path "$collectDir\\ad" | Out-Null
  try {
    Import-Module ActiveDirectory -ErrorAction Stop
    # KRBTGT info
    Get-ADUser krbtgt -Properties PasswordLastSet,Created |
      Select-Object Name,PasswordLastSet,Created |
      ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\ad\\krbtgt_info.csv" -Encoding UTF8
    # AdminSDHolder protected accounts
    Get-ADObject -Filter {AdminCount -eq 1} -Properties Name,ObjectClass,WhenChanged |
      Select-Object Name,ObjectClass,WhenChanged |
      ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\ad\\adminsdholder.csv" -Encoding UTF8
    # GPO list
    Get-GPO -All 2>$null |
      Select-Object DisplayName,GpoStatus,CreationTime,ModificationTime |
      ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\ad\\gpo_list.csv" -Encoding UTF8
    # DC replication partners
    Get-ADReplicationPartnerMetadata -Target $hostname -ErrorAction SilentlyContinue |
      Select-Object Partner,LastReplicationSuccess,ConsecutiveReplicationFailures |
      ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\ad\\replication.csv" -Encoding UTF8
    # Recently created AD users (last 30 days)
    $adCutoff = (Get-Date).AddDays(-30)
    Get-ADUser -Filter {Created -gt $adCutoff} -Properties Created,Enabled,LastLogonDate |
      Select-Object Name,SamAccountName,Created,Enabled,LastLogonDate |
      ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\ad\\recent_ad_users.csv" -Encoding UTF8
    # Disabled accounts
    Get-ADUser -Filter {Enabled -eq $false} -Properties WhenChanged |
      Select-Object Name,SamAccountName,WhenChanged |
      ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\ad\\disabled_accounts.csv" -Encoding UTF8
    # Domain trusts
    Get-ADTrust -Filter * 2>$null |
      Select-Object Name,Direction,TrustType,IntraForest |
      ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\ad\\domain_trusts.csv" -Encoding UTF8
    # SPN accounts (Kerberoast targets)
    Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName,PasswordLastSet 2>$null |
      Select-Object Name,SamAccountName,ServicePrincipalName,PasswordLastSet |
      ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\ad\\spn_accounts.csv" -Encoding UTF8
  } catch {
    "AD module not available: $_" | Out-File "$collectDir\\ad\\ad_error.txt" -Encoding UTF8
  }
}
`;

  const comprehensive = `
Write-Output "[STATUS] Building comprehensive file timeline..."
# File timeline: files modified in last 7 days across key directories
New-Item -ItemType Directory -Force -Path "$collectDir\\timeline" | Out-Null
$timelineDirs = @(
  "$env:WINDIR\\System32",
  "$env:WINDIR\\Temp",
  'C:\\Users',
  'C:\\ProgramData',
  "$env:WINDIR\\System32\\Tasks",
  'C:\\inetpub'
)
$timelineCutoff = (Get-Date).AddDays(-7)
$timelineResults = @()
foreach($tDir in $timelineDirs) {
  if(Test-Path $tDir) {
    $timelineResults += Get-ChildItem $tDir -Recurse -File -ErrorAction SilentlyContinue |
      Where-Object { $_.LastWriteTime -gt $timelineCutoff } |
      Select-Object -First 1000 @{N='Timestamp';E={$_.LastWriteTime.ToString('o')}},
        @{N='Size';E={$_.Length}},
        @{N='Owner';E={(Get-Acl $_.FullName -ErrorAction SilentlyContinue).Owner}},
        FullName
  }
}
$timelineResults | Sort-Object Timestamp -Descending | Select-Object -First 5000 |
  ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\timeline\\file_timeline.csv" -Encoding UTF8

Write-Output "[STATUS] Preserving full event logs..."
# Full event log preservation: 5000 events each from important log sources
$logSources = @(
  'Security','System','Application',
  'Microsoft-Windows-PowerShell/Operational',
  'Microsoft-Windows-Windows Defender/Operational',
  'Microsoft-Windows-TaskScheduler/Operational',
  'Microsoft-Windows-WMI-Activity/Operational',
  'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational',
  'Microsoft-Windows-Sysmon/Operational'
)
New-Item -ItemType Directory -Force -Path "$collectDir\\eventlogs" | Out-Null
foreach($logSrc in $logSources) {
  $safeName = $logSrc -replace '[/\\\\]','_'
  try {
    Get-WinEvent -LogName $logSrc -MaxEvents 5000 2>$null |
      Select-Object TimeCreated,Id,LevelDisplayName,ProviderName,Message |
      ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\eventlogs\\$safeName.csv" -Encoding UTF8
  } catch {}
}

Write-Output "[STATUS] Checking for log tampering..."
# Log tampering detection
$logStatus = @()
foreach($logSrc in $logSources) {
  try {
    $logInfo = Get-WinEvent -ListLog $logSrc -ErrorAction SilentlyContinue
    if($logInfo) {
      $logStatus += [PSCustomObject]@{
        LogName=$logSrc
        RecordCount=$logInfo.RecordCount
        FileSize=$logInfo.FileSize
        MaxSize=$logInfo.MaximumSizeInBytes
        LastWriteTime=$logInfo.LastWriteTime
        IsEnabled=$logInfo.IsEnabled
        LogMode=$logInfo.LogMode
      }
    }
  } catch {}
}
$logStatus | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\eventlogs\\log_status.csv" -Encoding UTF8

Write-Output "[STATUS] Checking System32 integrity..."
# System32 integrity: recent modifications to EXE/DLL files with SHA256
$sys32Cutoff = (Get-Date).AddDays(-30)
Get-ChildItem "$env:WINDIR\\System32" -File -ErrorAction SilentlyContinue |
  Where-Object { ($_.Extension -in @('.exe','.dll')) -and $_.LastWriteTime -gt $sys32Cutoff } |
  Select-Object -First 200 | ForEach-Object {
    $hash = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
    [PSCustomObject]@{ Path=$_.FullName; SHA256=$hash; Size=$_.Length; LastWrite=$_.LastWriteTime }
  } | ConvertTo-Csv -NoTypeInformation | Out-File "$collectDir\\integrity\\system32_recent_mods.csv" -Encoding UTF8

Write-Output "[STATUS] Exporting full security policy..."
# Full security policy with user rights
secedit /export /cfg "$collectDir\\system\\full_security_policy.inf" /areas USER_RIGHTS SECURITYPOLICY /quiet 2>$null
`;

  // Package into ZIP
  const packageScript = `
Write-Output "[STATUS] Packaging collection into ZIP..."
$zipName = ("forensics_{0}_{1}.zip" -f $hostname, $ts)
$zipPath = "$baseDir\\$zipName"
if(Test-Path $zipPath) { Remove-Item $zipPath -Force }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory($collectDir, $zipPath, 'Fastest', $false)
Remove-Item $collectDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Output "[ZIP] $zipPath"
Write-Output "WIN_FORENSICS_DONE:$zipPath"
`;

  let script = base;
  if (level === 'standard' || level === 'advanced' || level === 'comprehensive') {
    script += standard;
  }
  if (level === 'advanced' || level === 'comprehensive') {
    script += advanced;
  }
  if (level === 'comprehensive') {
    script += comprehensive;
  }
  script += packageScript;

  return script;
}


// ============================================================
// Analysis Script (12 categories)
// ============================================================

function buildWinAnalysisScript() {
  return `
$ErrorActionPreference='SilentlyContinue'

# ===== ENVIRONMENT =====
Write-Output "[CATEGORY:environment]"
Write-Output "[SEVERITY:info]"
$osInfo = Get-CimInstance Win32_OperatingSystem
$csInfo = Get-CimInstance Win32_ComputerSystem
Write-Output "[FINDING] Hostname: $env:COMPUTERNAME"
Write-Output "[FINDING] OS: $($osInfo.Caption) $($osInfo.Version)"
Write-Output "[FINDING] Last Boot: $($osInfo.LastBootUpTime)"
Write-Output "[FINDING] Domain: $($csInfo.Domain)"
Write-Output "[FINDING] DC: $($osInfo.ProductType -eq 2)"
Write-Output "[FINDING] Uptime: $(((Get-Date) - $osInfo.LastBootUpTime).ToString())"

# ===== WINDOWS DEFENDER =====
Write-Output "[CATEGORY:windows_defender]"
try {
  $mpStatus = Get-MpComputerStatus 2>$null
  if($mpStatus) {
    if(-not $mpStatus.RealTimeProtectionEnabled) {
      Write-Output "[SEVERITY:critical]"
      Write-Output "[FINDING] Real-time protection is DISABLED"
    }
    if(-not $mpStatus.AntivirusEnabled) {
      Write-Output "[SEVERITY:critical]"
      Write-Output "[FINDING] Antivirus is DISABLED"
    }
    Write-Output "[SEVERITY:info]"
    Write-Output "[FINDING] AV signature age: $($mpStatus.AntivirusSignatureAge) days (updated: $($mpStatus.AntivirusSignatureLastUpdated))"
    Write-Output "[FINDING] Last quick scan: $($mpStatus.QuickScanStartTime) (age: $($mpStatus.QuickScanAge) days)"
    Write-Output "[FINDING] Last full scan: $($mpStatus.FullScanStartTime) (age: $($mpStatus.FullScanAge) days)"
    Write-Output "[FINDING] Behavior monitor: $($mpStatus.BehaviorMonitorEnabled)"
    $threats = Get-MpThreatDetection 2>$null | Select-Object -First 10
    if($threats) {
      Write-Output "[SEVERITY:high]"
      foreach($t in $threats) {
        Write-Output "[FINDING] Defender threat: $($t.ThreatName) - Process: $($t.ProcessName) - Time: $($t.InitialDetectionTime)"
      }
    }
    $prefs = Get-MpPreference 2>$null
    if($prefs.ExclusionPath -or $prefs.ExclusionProcess -or $prefs.ExclusionExtension) {
      Write-Output "[SEVERITY:high]"
      foreach($ep in $prefs.ExclusionPath) { Write-Output "[FINDING] Defender exclusion path: $ep" }
      foreach($epr in $prefs.ExclusionProcess) { Write-Output "[FINDING] Defender exclusion process: $epr" }
      foreach($ee in $prefs.ExclusionExtension) { Write-Output "[FINDING] Defender exclusion extension: $ee" }
    }
  } else {
    Write-Output "[SEVERITY:critical]"
    Write-Output "[FINDING] Windows Defender not available or not responding"
  }
} catch {
  Write-Output "[SEVERITY:critical]"
  Write-Output "[FINDING] Cannot query Defender"
}

# ===== PROCESSES =====
Write-Output "[CATEGORY:processes]"
Write-Output "[SEVERITY:high]"
$allProcs = Get-CimInstance Win32_Process
$encodedProcs = $allProcs | Where-Object {
  $_.CommandLine -match '-[Ee]nc[o]?[d]?[e]?[d]?[Cc]?[o]?[m]?[m]?[a]?[n]?[d]?\\s' -or
  $_.CommandLine -match '-[Ee][Cc]\\s' -or
  $_.CommandLine -match 'FromBase64String'
}
foreach($p in $encodedProcs) {
  Write-Output "[FINDING] Encoded command detected: PID $($p.ProcessId) - $($p.Name) - $($p.CommandLine.Substring(0,[Math]::Min(200,$p.CommandLine.Length)))"
}

Write-Output "[SEVERITY:high]"
$tempProcs = $allProcs | Where-Object {
  $_.ExecutablePath -match '\\Temp\\' -or
  $_.ExecutablePath -match '\\tmp\\' -or
  $_.ExecutablePath -match '\\AppData\\Local\\Temp' -or
  $_.ExecutablePath -match '\\Downloads\\'
}
foreach($p in $tempProcs) {
  Write-Output "[FINDING] Process from temp/download dir: PID $($p.ProcessId) - $($p.Name) - $($p.ExecutablePath)"
}

Write-Output "[SEVERITY:medium]"
$noPathProcs = $allProcs | Where-Object {
  $_.Name -ne 'System' -and $_.Name -ne 'Idle' -and $_.Name -ne 'Registry' -and
  (-not $_.ExecutablePath -or $_.ExecutablePath -eq '')
}
foreach($p in $noPathProcs) {
  if($p.ProcessId -gt 4) {
    Write-Output "[FINDING] Process with no executable path: PID $($p.ProcessId) - $($p.Name)"
  }
}

# Parent-child anomalies
Write-Output "[SEVERITY:critical]"
$procLookup = @{}
$allProcs | ForEach-Object { $procLookup[$_.ProcessId] = $_ }
foreach($p in $allProcs) {
  $parent = $procLookup[$p.ParentProcessId]
  $parentName = if($parent) { $parent.Name } else { '' }
  if($parentName -match '(WINWORD|EXCEL|POWERPNT|OUTLOOK)\\.EXE' -and $p.Name -match '(cmd|powershell|pwsh|wscript|cscript|mshta)\\.exe') {
    Write-Output "[FINDING] Office spawned shell: $parentName -> $($p.Name) (PID $($p.ProcessId)) CMD: $($p.CommandLine)"
  }
}
# Fake svchost.exe
$svchosts = $allProcs | Where-Object { $_.Name -eq 'svchost.exe' }
foreach($sv in $svchosts) {
  if($sv.ExecutablePath -and $sv.ExecutablePath -notmatch '(?i)C:\\Windows\\(System32|SysWOW64)\\svchost\\.exe') {
    Write-Output "[FINDING] Fake svchost.exe: PID $($sv.ProcessId) running from $($sv.ExecutablePath)"
  }
}
# Multiple lsass.exe
$lsassCount = ($allProcs | Where-Object { $_.Name -eq 'lsass.exe' }).Count
if($lsassCount -gt 1) {
  Write-Output "[FINDING] Multiple lsass.exe processes ($lsassCount instances) - possible credential dumper"
}

# ===== PERSISTENCE =====
Write-Output "[CATEGORY:persistence]"
Write-Output "[SEVERITY:high]"
$suspTasks = Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
  $actions = $_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }
  $actionStr = $actions -join '; '
  if($actionStr -match '\\Temp\\|\\tmp\\|\\Downloads\\|powershell.*-[Ee]nc|cmd.*/[Cc].*http|mshta|regsvr32|rundll32.*javascript|certutil.*-urlcache|bitsadmin.*/transfer') {
    [PSCustomObject]@{ Name=$_.TaskName; Path=$_.TaskPath; Actions=$actionStr; Author=$_.Author }
  }
}
foreach($t in $suspTasks) {
  Write-Output "[FINDING] Suspicious scheduled task: $($t.Name) at $($t.Path) - Actions: $($t.Actions)"
}

Write-Output "[SEVERITY:critical]"
$wmiConsumers = Get-WmiObject -Namespace root\\subscription -Class __EventConsumer 2>$null
foreach($c in $wmiConsumers) {
  $detail = if($c.CommandLineTemplate) { $c.CommandLineTemplate } elseif($c.ScriptText) { "Script: $($c.ScriptText.Substring(0,[Math]::Min(100,$c.ScriptText.Length)))" } else { $c.__CLASS }
  Write-Output "[FINDING] WMI event consumer (persistence): $($c.Name) - $detail"
}

Write-Output "[SEVERITY:high]"
$autorunKeys = @(
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
  'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
  'HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce'
)
foreach($key in $autorunKeys) {
  if(Test-Path $key) {
    $props = Get-ItemProperty $key -ErrorAction SilentlyContinue
    $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
      $val = $_.Value
      if($val -match '\\Temp\\|\\tmp\\|\\Downloads\\|powershell.*-[Ee]nc|mshta|regsvr32|cmd.*/[Cc].*http|certutil') {
        Write-Output "[FINDING] Suspicious autorun: $key\\$($_.Name) = $val"
      }
    }
  }
}

Write-Output "[SEVERITY:high]"
$winlogon = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -ErrorAction SilentlyContinue
if($winlogon.Shell -and $winlogon.Shell -ne 'explorer.exe') {
  Write-Output "[FINDING] Winlogon Shell modified: $($winlogon.Shell)"
}
if($winlogon.Userinit -and $winlogon.Userinit -notmatch '^C:\\Windows\\system32\\userinit.exe,?$') {
  Write-Output "[FINDING] Winlogon Userinit modified: $($winlogon.Userinit)"
}

Write-Output "[SEVERITY:critical]"
$ifeo = Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options' -ErrorAction SilentlyContinue
foreach($entry in $ifeo) {
  $debugger = (Get-ItemProperty $entry.PSPath -ErrorAction SilentlyContinue).Debugger
  if($debugger) {
    Write-Output "[FINDING] IFEO debugger hijack: $($entry.PSChildName) -> $debugger"
  }
}

# LSA SSP injection
Write-Output "[SEVERITY:critical]"
$lsaPath = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa'
if(Test-Path $lsaPath) {
  $lsa = Get-ItemProperty $lsaPath
  $secPkgs = $lsa.'Security Packages'
  $defaultPkgs = @('','kerberos','msv1_0','schannel','wdigest','tspkg','pku2u')
  foreach($pkg in $secPkgs) {
    if($pkg -and $pkg -notin $defaultPkgs) {
      Write-Output "[FINDING] Non-default LSA Security Package: $pkg (possible SSP injection)"
    }
  }
}

# Boot Execute
$bootExec = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager' -ErrorAction SilentlyContinue).BootExecute
if($bootExec) {
  foreach($be in $bootExec) {
    if($be -and $be -ne 'autocheck autochk *') {
      Write-Output "[SEVERITY:high]"
      Write-Output "[FINDING] Non-standard Boot Execute entry: $be"
    }
  }
}

# PowerShell profiles
Write-Output "[SEVERITY:high]"
$psProfilePaths = @(
  "$env:WINDIR\\System32\\WindowsPowerShell\\v1.0\\profile.ps1",
  "$env:WINDIR\\System32\\WindowsPowerShell\\v1.0\\Microsoft.PowerShell_profile.ps1"
)
foreach($pp in $psProfilePaths) {
  if(Test-Path $pp) {
    Write-Output "[FINDING] System-wide PowerShell profile exists: $pp ($(Get-Item $pp).Length bytes)"
  }
}

# Unquoted service paths
Write-Output "[SEVERITY:medium]"
Get-WmiObject Win32_Service 2>$null | Where-Object {
  $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -notmatch '^[A-Za-z]:\\Windows\\' -and $_.PathName -match ' '
} | ForEach-Object {
  Write-Output "[FINDING] Unquoted service path: $($_.Name) -> $($_.PathName)"
}

# ===== ROOTKIT INDICATORS =====
Write-Output "[CATEGORY:rootkit_indicators]"
Write-Output "[SEVERITY:critical]"

# Hidden services: in registry but not in Get-Service
$regServices = Get-ChildItem 'HKLM:\\SYSTEM\\CurrentControlSet\\Services' -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName }
$runningServices = Get-Service | ForEach-Object { $_.Name }
$hiddenSvcs = $regServices | Where-Object { $_ -notin $runningServices } | Where-Object {
  $imgPath = (Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$_" -ErrorAction SilentlyContinue).ImagePath
  $imgPath -and $imgPath -notmatch '\\drivers\\' -and $imgPath -match '\\.(exe|dll|sys)'
} | Select-Object -First 20
foreach($hs in $hiddenSvcs) {
  $imgPath = (Get-ItemProperty "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$hs" -ErrorAction SilentlyContinue).ImagePath
  Write-Output "[FINDING] Hidden service (registry only): $hs -> $imgPath"
}

# AppInit_DLLs active
Write-Output "[SEVERITY:high]"
$appInit = Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows' -ErrorAction SilentlyContinue
if($appInit.LoadAppInit_DLLs -eq 1 -and $appInit.AppInit_DLLs) {
  Write-Output "[FINDING] AppInit_DLLs active and loaded: $($appInit.AppInit_DLLs)"
}

# ===== NETWORK =====
Write-Output "[CATEGORY:network]"
Write-Output "[SEVERITY:medium]"
$commonPorts = @(22,80,443,445,135,139,389,636,3389,5985,5986,47001,53,88,464,3268,3269,4505,4506)
$seenPorts = @{}
$listening = Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -notin $commonPorts -and $_.LocalPort -gt 1024 }
foreach($conn in $listening) {
  $key = "$($conn.LocalPort)-$($conn.OwningProcess)"
  if(-not $seenPorts[$key]) {
    $seenPorts[$key] = $true
    $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
    Write-Output "[FINDING] Unusual listening port: $($conn.LocalAddress):$($conn.LocalPort) - PID $($conn.OwningProcess) ($($proc.ProcessName))"
  }
}

Write-Output "[SEVERITY:medium]"
$established = Get-NetTCPConnection -State Established | Where-Object {
  $_.RemoteAddress -ne '127.0.0.1' -and $_.RemoteAddress -ne '::1' -and
  $_.RemoteAddress -notmatch '^10\\.' -and $_.RemoteAddress -notmatch '^172\\.(1[6-9]|2[0-9]|3[01])\\.' -and
  $_.RemoteAddress -notmatch '^192\\.168\\.'
} | Select-Object -First 20
foreach($conn in $established) {
  $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
  Write-Output "[FINDING] External connection: $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort) - PID $($conn.OwningProcess) ($($proc.ProcessName))"
}

# ===== USERS =====
Write-Output "[CATEGORY:users]"
Write-Output "[SEVERITY:high]"
$cutoff = (Get-Date).AddDays(-7)
$recentUsers = Get-LocalUser | Where-Object { $_.Created -gt $cutoff -or $_.PasswordLastSet -gt $cutoff }
foreach($u in $recentUsers) {
  Write-Output "[FINDING] Recently created/modified user: $($u.Name) - Created: $($u.Created) - Enabled: $($u.Enabled)"
}

Write-Output "[SEVERITY:critical]"
$hiddenUsers = Get-LocalUser | Where-Object { $_.Name -match '\\$$' -and $_.Enabled }
foreach($u in $hiddenUsers) {
  Write-Output "[FINDING] Hidden account detected ($ suffix): $($u.Name)"
}

Write-Output "[SEVERITY:info]"
$admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
foreach($a in $admins) {
  Write-Output "[FINDING] Administrator group member: $($a.Name) ($($a.ObjectClass))"
}

# ===== EVENT LOG ANALYSIS =====
Write-Output "[CATEGORY:event_log_analysis]"
Write-Output "[SEVERITY:high]"
$last24h = (Get-Date).AddHours(-24)
$failedLogons = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=$last24h} -MaxEvents 500 2>$null
$failCount = ($failedLogons | Measure-Object).Count
if($failCount -gt 10) {
  Write-Output "[FINDING] Brute force detected: $failCount failed logons in last 24h"
  $failedLogons | Group-Object { ([xml]$_.ToXml()).Event.EventData.Data | Where-Object Name -eq 'IpAddress' | Select-Object -ExpandProperty '#text' } |
    Sort-Object Count -Descending | Select-Object -First 5 | ForEach-Object {
      Write-Output "[FINDING] Failed logon source: $($_.Name) - $($_.Count) attempts"
    }
}

Write-Output "[SEVERITY:critical]"
$cleared = Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} -MaxEvents 10 2>$null
foreach($c in $cleared) {
  Write-Output "[FINDING] Audit log cleared at $($c.TimeCreated)"
}

Write-Output "[SEVERITY:high]"
$svcCutoff = (Get-Date).AddDays(-7)
$newSvcs = Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime=$svcCutoff} -MaxEvents 50 2>$null
foreach($s in $newSvcs) {
  $xml=[xml]$s.ToXml()
  $d=$xml.Event.EventData.Data
  $svcName=($d | Where-Object Name -eq 'ServiceName').'#text'
  $imgPath=($d | Where-Object Name -eq 'ImagePath').'#text'
  Write-Output "[FINDING] New service installed: $svcName -> $imgPath (at $($s.TimeCreated))"
}

$acctEvents = Get-WinEvent -FilterHashtable @{LogName='Security';Id=@(4720,4726);StartTime=$svcCutoff} -MaxEvents 50 2>$null
foreach($ae in $acctEvents) {
  $xml=[xml]$ae.ToXml()
  $d=$xml.Event.EventData.Data
  $targetUser=($d | Where-Object Name -eq 'TargetUserName').'#text'
  $subjectUser=($d | Where-Object Name -eq 'SubjectUserName').'#text'
  $action = if($ae.Id -eq 4720){'created'}else{'deleted'}
  Write-Output "[FINDING] Account $action : $targetUser (by $subjectUser at $($ae.TimeCreated))"
}

$explicitCred = Get-WinEvent -FilterHashtable @{LogName='Security';Id=4648} -MaxEvents 20 2>$null
if($explicitCred.Count -gt 5) {
  Write-Output "[SEVERITY:medium]"
  Write-Output "[FINDING] $($explicitCred.Count) explicit credential logon events (4648) - possible pass-the-hash"
}

$defenderAlerts = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';Id=@(1116,1117)} -MaxEvents 20 2>$null
if($defenderAlerts) {
  Write-Output "[SEVERITY:high]"
  foreach($da in $defenderAlerts) {
    Write-Output "[FINDING] Defender alert at $($da.TimeCreated): $($da.Message.Substring(0,[Math]::Min(200,$da.Message.Length)))"
  }
}

# ===== FILE INTEGRITY =====
Write-Output "[CATEGORY:file_integrity]"
Write-Output "[SEVERITY:high]"
$intCutoff = (Get-Date).AddDays(-30)
Get-ChildItem "$env:WINDIR\\System32\\*.exe" -ErrorAction SilentlyContinue |
  Where-Object { $_.LastWriteTime -gt $intCutoff } | Select-Object -First 50 | ForEach-Object {
    $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue
    if($sig.Status -ne 'Valid') {
      Write-Output "[FINDING] Unsigned/modified System32 binary: $($_.Name) (status: $($sig.Status), modified: $($_.LastWriteTime))"
    }
  }

# ===== SECURITY POLICY =====
Write-Output "[CATEGORY:security_policy]"
Write-Output "[SEVERITY:medium]"
$netAccounts = net accounts 2>$null
if($netAccounts) {
  $minLen = $netAccounts | Select-String 'Minimum password length' | ForEach-Object { ($_ -split ':\\s*')[1].Trim() }
  $lockoutThreshold = $netAccounts | Select-String 'Lockout threshold' | ForEach-Object { ($_ -split ':\\s*')[1].Trim() }
  if($minLen -and [int]$minLen -lt 8) {
    Write-Output "[FINDING] Weak minimum password length: $minLen (should be 8+)"
  }
  if($lockoutThreshold -eq 'Never' -or $lockoutThreshold -eq '0') {
    Write-Output "[FINDING] No account lockout threshold configured"
  }
}
try {
  $mpStatus2 = Get-MpComputerStatus 2>$null
  if($mpStatus2 -and -not $mpStatus2.RealTimeProtectionEnabled) {
    Write-Output "[SEVERITY:critical]"
    Write-Output "[FINDING] Windows Defender real-time protection is DISABLED"
  }
} catch {}

# ===== CREDENTIAL EXPOSURE =====
Write-Output "[CATEGORY:credential_exposure]"
Write-Output "[SEVERITY:critical]"
$wdigest = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -ErrorAction SilentlyContinue).UseLogonCredential
if($wdigest -eq 1) {
  Write-Output "[FINDING] WDigest UseLogonCredential=1 - plaintext passwords stored in memory (mimikatz target)"
}

Write-Output "[SEVERITY:high]"
$runAsPPL = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -ErrorAction SilentlyContinue).RunAsPPL
if(-not $runAsPPL -or $runAsPPL -eq 0) {
  Write-Output "[FINDING] LSA Protection (RunAsPPL) not enabled - lsass.exe vulnerable to credential dumping"
}

Write-Output "[SEVERITY:info]"
$credman = cmdkey /list 2>$null
if($credman) {
  $credCount = ($credman | Select-String 'Target:').Count
  if($credCount -gt 0) {
    Write-Output "[FINDING] $credCount stored credentials in Credential Manager"
  }
}

# ===== AD-SPECIFIC (if DC) =====
$isDC = (Get-CimInstance Win32_OperatingSystem).ProductType -eq 2
if($isDC) {
  Write-Output "[CATEGORY:active_directory]"
  try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Output "[SEVERITY:high]"
    $krbtgt = Get-ADUser krbtgt -Properties PasswordLastSet
    $krbtgtAge = ((Get-Date) - $krbtgt.PasswordLastSet).Days
    if($krbtgtAge -gt 180) {
      Write-Output "[FINDING] KRBTGT password is $krbtgtAge days old (should be rotated regularly)"
    }
    Write-Output "[SEVERITY:medium]"
    $adminSD = Get-ADObject -Filter {AdminCount -eq 1} -Properties Name,ObjectClass,WhenChanged
    $unexpectedAdmin = $adminSD | Where-Object { $_.ObjectClass -eq 'user' -and $_.Name -notin @('Administrator','krbtgt') }
    foreach($obj in $unexpectedAdmin) {
      Write-Output "[FINDING] AdminSDHolder protected account: $($obj.Name) (class: $($obj.ObjectClass), changed: $($obj.WhenChanged))"
    }
    Write-Output "[SEVERITY:high]"
    $spnAccts = Get-ADUser -Filter "ServicePrincipalName -ne '$null'" -Properties ServicePrincipalName,PasswordLastSet 2>$null
    foreach($spn in $spnAccts) {
      Write-Output "[FINDING] SPN account (Kerberoast target): $($spn.Name) - PW set: $($spn.PasswordLastSet)"
    }
  } catch {
    Write-Output "[SEVERITY:info]"
    Write-Output "[FINDING] AD module not available for DC checks"
  }
}

Write-Output "WIN_ANALYSIS_DONE"
`;
}

// ============================================================
// Quick Scan Script (enhanced, live check ~30s)
// ============================================================

function buildWinQuickScanScript() {
  return `
$ErrorActionPreference='SilentlyContinue'

Write-Output "[CATEGORY:windows_defender]"
# Defender real-time protection status
try {
  $mpStatus = Get-MpComputerStatus 2>$null
  if($mpStatus) {
    if(-not $mpStatus.RealTimeProtectionEnabled) {
      Write-Output "[SEVERITY:critical]"
      Write-Output "[FINDING] Defender real-time protection DISABLED"
    }
    $recentThreats = Get-MpThreatDetection 2>$null | Select-Object -First 5
    if($recentThreats) {
      Write-Output "[SEVERITY:high]"
      foreach($t in $recentThreats) {
        Write-Output "[FINDING] Defender threat: $($t.ThreatName) at $($t.InitialDetectionTime)"
      }
    }
  } else {
    Write-Output "[SEVERITY:critical]"
    Write-Output "[FINDING] Defender not available"
  }
} catch {}

Write-Output "[CATEGORY:event_log_analysis]"
# Failed logons in last 24h
Write-Output "[SEVERITY:high]"
$last24h = (Get-Date).AddHours(-24)
$failCount = (Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=$last24h} -MaxEvents 500 2>$null | Measure-Object).Count
if($failCount -gt 10) {
  Write-Output "[FINDING] $failCount failed logons in last 24h (brute force indicator)"
}

# Audit log cleared (1102)
Write-Output "[SEVERITY:critical]"
$cleared = Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102} -MaxEvents 5 2>$null
foreach($c in $cleared) {
  Write-Output "[FINDING] Audit log cleared at $($c.TimeCreated)"
}

# New services (7045) in last 7 days
Write-Output "[SEVERITY:high]"
$svcCutoff = (Get-Date).AddDays(-7)
$newSvcs = Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime=$svcCutoff} -MaxEvents 20 2>$null
foreach($s in $newSvcs) {
  $xml=[xml]$s.ToXml()
  $d=$xml.Event.EventData.Data
  $svcName=($d | Where-Object Name -eq 'ServiceName').'#text'
  $imgPath=($d | Where-Object Name -eq 'ImagePath').'#text'
  Write-Output "[FINDING] New service: $svcName -> $imgPath"
}

# Account changes in last 7 days
$acctEvents = Get-WinEvent -FilterHashtable @{LogName='Security';Id=@(4720,4726);StartTime=$svcCutoff} -MaxEvents 20 2>$null
foreach($ae in $acctEvents) {
  $xml=[xml]$ae.ToXml()
  $d=$xml.Event.EventData.Data
  $targetUser=($d | Where-Object Name -eq 'TargetUserName').'#text'
  $action = if($ae.Id -eq 4720){'created'}else{'deleted'}
  Write-Output "[FINDING] Account $action : $targetUser at $($ae.TimeCreated)"
}

Write-Output "[CATEGORY:processes]"
Write-Output "[SEVERITY:high]"
# Encoded commands
Get-CimInstance Win32_Process | Where-Object {
  $_.CommandLine -match '-[Ee]nc[o]?[d]?\\s' -or $_.CommandLine -match 'FromBase64String'
} | ForEach-Object {
  Write-Output "[FINDING] Encoded command: PID $($_.ProcessId) - $($_.Name)"
}

# Temp dir processes
Get-CimInstance Win32_Process | Where-Object {
  $_.ExecutablePath -match '\\Temp\\|\\Downloads\\'
} | ForEach-Object {
  Write-Output "[FINDING] Process from temp/download: PID $($_.ProcessId) - $($_.Name) - $($_.ExecutablePath)"
}

# Fake svchost
Write-Output "[SEVERITY:critical]"
Get-CimInstance Win32_Process | Where-Object { $_.Name -eq 'svchost.exe' } | ForEach-Object {
  if($_.ExecutablePath -and $_.ExecutablePath -notmatch '(?i)C:\\Windows\\(System32|SysWOW64)\\svchost\\.exe') {
    Write-Output "[FINDING] Fake svchost.exe: PID $($_.ProcessId) from $($_.ExecutablePath)"
  }
}

Write-Output "[CATEGORY:persistence]"
Write-Output "[SEVERITY:critical]"
# IFEO debugger hijacks
$ifeo = Get-ChildItem 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options' -ErrorAction SilentlyContinue
foreach($entry in $ifeo) {
  $debugger = (Get-ItemProperty $entry.PSPath -ErrorAction SilentlyContinue).Debugger
  if($debugger) {
    Write-Output "[FINDING] IFEO debugger hijack: $($entry.PSChildName) -> $debugger"
  }
}

# WMI subscriptions
$wmi = Get-WmiObject -Namespace root\\subscription -Class __EventConsumer 2>$null
foreach($c in $wmi) {
  Write-Output "[FINDING] WMI persistence: $($c.Name)"
}

Write-Output "[SEVERITY:high]"
# Suspicious tasks
Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object {
  $a = ($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join '; '
  if($a -match '\\Temp\\|powershell.*-[Ee]nc|cmd.*/[Cc].*http|mshta|regsvr32') {
    Write-Output "[FINDING] Suspicious task: $($_.TaskName) - $a"
  }
}

Write-Output "[CATEGORY:network]"
Write-Output "[SEVERITY:medium]"
# Unusual listeners
$common = @(22,80,443,445,135,139,389,636,3389,5985,5986,47001,53,88,464,3268,3269,4505,4506)
$seen = @{}
Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -notin $common -and $_.LocalPort -gt 1024 } | ForEach-Object {
  $key = "$($_.LocalPort)-$($_.OwningProcess)"
  if(-not $seen[$key]) {
    $seen[$key] = $true
    $proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    Write-Output "[FINDING] Unusual listener: port $($_.LocalPort) - $($proc.ProcessName)"
  }
}

Write-Output "[CATEGORY:users]"
Write-Output "[SEVERITY:critical]"
# Hidden accounts
Get-LocalUser | Where-Object { $_.Name -match '\\$$' -and $_.Enabled } | ForEach-Object {
  Write-Output "[FINDING] Hidden account: $($_.Name)"
}
Write-Output "[SEVERITY:high]"
# Recent users
$cutoff = (Get-Date).AddDays(-7)
Get-LocalUser | Where-Object { $_.Created -gt $cutoff } | ForEach-Object {
  Write-Output "[FINDING] Recently created user: $($_.Name) - $($_.Created)"
}

Write-Output "[CATEGORY:credential_exposure]"
Write-Output "[SEVERITY:critical]"
$wdigest = (Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -ErrorAction SilentlyContinue).UseLogonCredential
if($wdigest -eq 1) {
  Write-Output "[FINDING] WDigest plaintext credentials enabled (mimikatz target)"
}

Write-Output "WIN_SCAN_DONE"
`;
}

// ============================================================
// Deep Scan Script (slow, ~5-10 min: Defender scan, SFC, DISM, signatures)
// ============================================================

function buildWinScanScript() {
  return `
$ErrorActionPreference='SilentlyContinue'
Write-Output "[SCAN_PHASE] Starting Windows deep security scan..."
Write-Output "[SCAN_PHASE] Timestamp: $(Get-Date -Format 'o')"

$baseDir = "C:\\Windows\\Temp\\forensics"
$scanDir = "$baseDir\\deepscan_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
New-Item -ItemType Directory -Force -Path $scanDir | Out-Null

# Find most recent collection ZIP
$latestZip = Get-ChildItem "$baseDir\\forensics_*.zip" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1

# =============================================
# 1. WINDOWS DEFENDER QUICK SCAN
# =============================================
Write-Output "[SCAN_STATUS] defender:running"
try {
  Start-MpScan -ScanType QuickScan -ErrorAction Stop
  Write-Output "[SCAN_STATUS] defender:done"
  $threats = Get-MpThreatDetection 2>$null
  $threatCount = ($threats | Measure-Object).Count
  Write-Output "[SCAN_RESULT] defender=$threatCount threats"
  if($threats) {
    $threats | Select-Object ThreatID,ThreatName,DomainUser,ProcessName,InitialDetectionTime,ActionSuccess,Resources |
      ConvertTo-Csv -NoTypeInformation | Out-File "$scanDir\\defender_threats.csv" -Encoding UTF8
  }
  Get-MpThreat 2>$null | Select-Object ThreatID,ThreatName,SeverityID,IsActive,DidThreatExecute |
    ConvertTo-Csv -NoTypeInformation | Out-File "$scanDir\\defender_threat_history.csv" -Encoding UTF8
} catch {
  Write-Output "[SCAN_STATUS] defender:failed"
  Write-Output "[SCAN_RESULT] defender=error: $_"
}

# =============================================
# 2. SFC (System File Checker)
# =============================================
Write-Output "[SCAN_STATUS] sfc:running"
$sfcOutput = sfc /verifyonly 2>&1
$sfcOutput | Out-File "$scanDir\\sfc_results.txt" -Encoding UTF8
$sfcViolations = ($sfcOutput | Select-String 'integrity violations').Count
if($sfcOutput | Select-String 'found integrity violations') {
  Write-Output "[SCAN_RESULT] sfc=integrity violations found"
} elseif($sfcOutput | Select-String 'did not find any integrity violations') {
  Write-Output "[SCAN_RESULT] sfc=clean"
} else {
  Write-Output "[SCAN_RESULT] sfc=check log"
}
Write-Output "[SCAN_STATUS] sfc:done"

# =============================================
# 3. DISM Health Check
# =============================================
Write-Output "[SCAN_STATUS] dism:running"
$dismOutput = DISM /Online /Cleanup-Image /ScanHealth 2>&1
$dismOutput | Out-File "$scanDir\\dism_results.txt" -Encoding UTF8
if($dismOutput | Select-String 'component store is repairable') {
  Write-Output "[SCAN_RESULT] dism=repairable"
} elseif($dismOutput | Select-String 'No component store corruption detected') {
  Write-Output "[SCAN_RESULT] dism=clean"
} else {
  Write-Output "[SCAN_RESULT] dism=check log"
}
Write-Output "[SCAN_STATUS] dism:done"

# =============================================
# 4. AUTHENTICODE VERIFICATION (System32 EXEs)
# =============================================
Write-Output "[SCAN_STATUS] authenticode:running"
$unsignedCount = 0
$unsignedFiles = @()
Get-ChildItem "$env:WINDIR\\System32\\*.exe" -ErrorAction SilentlyContinue | Select-Object -First 200 | ForEach-Object {
  $sig = Get-AuthenticodeSignature $_.FullName -ErrorAction SilentlyContinue
  if($sig.Status -ne 'Valid') {
    $unsignedCount++
    $unsignedFiles += [PSCustomObject]@{ Path=$_.FullName; Status=$sig.Status; Size=$_.Length; LastWrite=$_.LastWriteTime }
  }
}
if($unsignedFiles.Count -gt 0) {
  $unsignedFiles | ConvertTo-Csv -NoTypeInformation | Out-File "$scanDir\\unsigned_binaries.csv" -Encoding UTF8
}
Write-Output "[SCAN_RESULT] authenticode=$unsignedCount unsigned binaries"
Write-Output "[SCAN_STATUS] authenticode:done"

# =============================================
# 5. SUSPICIOUS FILE SCAN (temp directories)
# =============================================
Write-Output "[SCAN_STATUS] suspicious_files:running"
$suspExts = @('.exe','.dll','.ps1','.bat','.cmd','.vbs','.js','.hta','.scr','.com')
$suspDirs = @("$env:TEMP","$env:WINDIR\\Temp","C:\\Users\\*\\AppData\\Local\\Temp","C:\\Users\\*\\Downloads")
$suspFiles = @()
foreach($sd in $suspDirs) {
  Get-ChildItem $sd -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -in $suspExts } | Select-Object -First 100 | ForEach-Object {
      $hash = (Get-FileHash $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash
      $suspFiles += [PSCustomObject]@{ Path=$_.FullName; SHA256=$hash; Size=$_.Length; LastWrite=$_.LastWriteTime; Extension=$_.Extension }
    }
}
if($suspFiles.Count -gt 0) {
  $suspFiles | ConvertTo-Csv -NoTypeInformation | Out-File "$scanDir\\suspicious_file_hashes.csv" -Encoding UTF8
}
Write-Output "[SCAN_RESULT] suspicious_files=$($suspFiles.Count) files hashed"
Write-Output "[SCAN_STATUS] suspicious_files:done"

# =============================================
# UPDATE ZIP WITH SCAN RESULTS
# =============================================
if($latestZip) {
  Write-Output "[SCAN_PHASE] Updating ZIP with scan results..."
  try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::Open($latestZip.FullName, 'Update')
    Get-ChildItem $scanDir -File -Recurse | ForEach-Object {
      $entryName = "scanning/$($_.Name)"
      $entry = $zip.CreateEntry($entryName)
      $writer = New-Object System.IO.StreamWriter($entry.Open())
      $writer.Write([System.IO.File]::ReadAllText($_.FullName))
      $writer.Close()
    }
    $zip.Dispose()
    Write-Output "[SCAN_PHASE] Updated: $($latestZip.FullName)"
  } catch {
    Write-Output "[SCAN_PHASE] Failed to update ZIP: $_"
  }
}

# Cleanup
Remove-Item $scanDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Output ""
Write-Output "[SCAN_PHASE] Deep scan complete"
Write-Output "[SCAN_SUMMARY]"
Write-Output "  defender: $threatCount threats"
Write-Output "  sfc: $(if($sfcOutput | Select-String 'did not find'){'clean'}else{'check results'})"
Write-Output "  dism: $(if($dismOutput | Select-String 'No component store'){'clean'}else{'check results'})"
Write-Output "  authenticode: $unsignedCount unsigned"
Write-Output "  suspicious_files: $($suspFiles.Count) hashed"
Write-Output "WIN_DEEP_SCAN_DONE"
`;
}

module.exports = router;
