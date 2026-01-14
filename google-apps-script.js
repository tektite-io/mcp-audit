// Google Apps Script for MCP Audit Analytics
// Spreadsheet: https://docs.google.com/spreadsheets/d/14az_9cLskCROPs1NvF01nlP5WZaeEsdUDdyhPXsut_U
//
// This script receives analytics events from the MCP Audit web app
// and logs them to separate sheets based on event type.
//
// HOW TO UPDATE:
// 1. Go to https://script.google.com
// 2. Open the project linked to your spreadsheet
// 3. Replace the code with this file's contents
// 4. Click Deploy → Manage deployments → Edit (pencil icon)
// 5. Select "New version" and click Deploy

function doGet(e) {
  try {
    const params = e.parameter;
    const event = params.event || 'unknown';
    const timestamp = new Date().toISOString();

    const ss = SpreadsheetApp.getActiveSpreadsheet();

    // Route to appropriate sheet based on event type
    if (event === 'cli_download') {
      logCliDownload(ss, timestamp, params);
    } else if (event === 'scan_completed') {
      logScanCompleted(ss, timestamp, params);
    } else if (event === 'scan_started') {
      logScanStarted(ss, timestamp, params);
    } else if (event === 'scan_error') {
      logScanError(ss, timestamp, params);
    } else if (event === 'export') {
      logExport(ss, timestamp, params);
    } else if (event === 'report_sent') {
      logReportSent(ss, timestamp, params);
    } else {
      logGeneralEvent(ss, timestamp, params);
    }

    return ContentService.createTextOutput('OK');
  } catch (error) {
    return ContentService.createTextOutput('Error: ' + error.message);
  }
}

// ============ CLI Downloads ============
function logCliDownload(ss, timestamp, params) {
  let sheet = ss.getSheetByName('CLI Downloads');

  // Create sheet if it doesn't exist
  if (!sheet) {
    sheet = ss.insertSheet('CLI Downloads');
    sheet.appendRow(['Timestamp', 'Event', 'Source']);
    // Format header row
    sheet.getRange(1, 1, 1, 3).setFontWeight('bold');
  }

  sheet.appendRow([
    timestamp,
    params.event,
    params.source || ''
  ]);
}

// ============ Scan Events ============
function logScanCompleted(ss, timestamp, params) {
  let sheet = ss.getSheetByName('Scans');

  if (!sheet) {
    sheet = ss.insertSheet('Scans');
    sheet.appendRow(['Timestamp', 'Status', 'Source', 'Org/User', 'MCPs Found', 'Known MCPs', 'Unknown MCPs']);
    sheet.getRange(1, 1, 1, 7).setFontWeight('bold');
  }

  sheet.appendRow([
    timestamp,
    'completed',
    params.source || '',
    params.org_name || '',
    parseInt(params.mcps_found) || 0,
    parseInt(params.known_mcps) || 0,
    parseInt(params.unknown_mcps) || 0
  ]);
}

function logScanStarted(ss, timestamp, params) {
  let sheet = ss.getSheetByName('Scans');

  if (!sheet) {
    sheet = ss.insertSheet('Scans');
    sheet.appendRow(['Timestamp', 'Status', 'Source', 'Org/User', 'MCPs Found', 'Known MCPs', 'Unknown MCPs']);
    sheet.getRange(1, 1, 1, 7).setFontWeight('bold');
  }

  sheet.appendRow([
    timestamp,
    'started',
    params.source || '',
    params.org_name || '',
    '', '', ''
  ]);
}

function logScanError(ss, timestamp, params) {
  let sheet = ss.getSheetByName('Scans');

  if (!sheet) {
    sheet = ss.insertSheet('Scans');
    sheet.appendRow(['Timestamp', 'Status', 'Source', 'Org/User', 'MCPs Found', 'Known MCPs', 'Unknown MCPs']);
    sheet.getRange(1, 1, 1, 7).setFontWeight('bold');
  }

  sheet.appendRow([
    timestamp,
    'error',
    params.source || '',
    params.org_name || '',
    '', '', ''
  ]);
}

// ============ Exports ============
function logExport(ss, timestamp, params) {
  let sheet = ss.getSheetByName('Exports');

  if (!sheet) {
    sheet = ss.insertSheet('Exports');
    sheet.appendRow(['Timestamp', 'Format', 'MCPs Count']);
    sheet.getRange(1, 1, 1, 3).setFontWeight('bold');
  }

  sheet.appendRow([
    timestamp,
    params.export_format || '',
    parseInt(params.mcps_found) || 0
  ]);
}

// ============ Email Reports (Lead Capture) ============
function logReportSent(ss, timestamp, params) {
  let sheet = ss.getSheetByName('Email Reports');

  if (!sheet) {
    sheet = ss.insertSheet('Email Reports');
    sheet.appendRow(['Timestamp', 'Email', 'Source', 'Scan Type', 'MCPs', 'Secrets', 'APIs', 'Models']);
    sheet.getRange(1, 1, 1, 8).setFontWeight('bold');
  }

  sheet.appendRow([
    timestamp,
    params.email || '',
    params.source || '',
    params.scan_type || '',
    parseInt(params.mcps) || 0,
    parseInt(params.secrets) || 0,
    parseInt(params.apis) || 0,
    parseInt(params.models) || 0
  ]);
}

// ============ General Events (page views, tab clicks, etc.) ============
function logGeneralEvent(ss, timestamp, params) {
  let sheet = ss.getSheetByName('Events');

  if (!sheet) {
    sheet = ss.insertSheet('Events');
    sheet.appendRow(['Timestamp', 'Event', 'Source', 'Details']);
    sheet.getRange(1, 1, 1, 4).setFontWeight('bold');
  }

  // Remove event from params to avoid duplication in details
  const detailParams = {...params};
  delete detailParams.event;
  const details = Object.keys(detailParams).length > 0 ? JSON.stringify(detailParams) : '';

  sheet.appendRow([
    timestamp,
    params.event,
    params.source || '',
    details
  ]);
}
