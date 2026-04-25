document.addEventListener('DOMContentLoaded', () => {
  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');
  const textArea = document.getElementById('email-text');
  const analyzeBtn = document.getElementById('analyze-btn');
  const emailPreviewBtn = document.getElementById('email-preview-btn');
  const resultsPanel = document.getElementById('results-panel');
  const batchStatus = document.getElementById('batch-status');
  const themeToggle = document.getElementById('theme-toggle');
  
  // Modal Elements
  const modal = document.getElementById('preview-modal');
  const modalBody = document.getElementById('preview-body');
  const modalAlert = document.getElementById('modal-alert');
  const closeModal = document.getElementById('close-modal');
  const modalOverlay = document.querySelector('.modal-overlay');
  
  // API settings
  const API_BASE = 'http://localhost:8000';
  const API_KEY = 'SOC-API-KEY-123'; // Matches backend demo key

  let uploadedFiles = [];
  let currentFileIndex = 0;
  let currentAnalysisText = "";
  let lastAnalysisResult = null;

  // --- Theme Toggle --- //
  themeToggle.addEventListener('click', () => {
    document.body.classList.toggle('theme-light');
    document.body.classList.toggle('theme-cyber');
    
    // Save preference
    const isLight = document.body.classList.contains('theme-light');
    localStorage.setItem('theme', isLight ? 'light' : 'cyber');
  });

  // Load saved theme
  const savedTheme = localStorage.getItem('theme');
  if (savedTheme === 'light') {
    document.body.classList.remove('theme-cyber');
    document.body.classList.add('theme-light');
  }

  // --- Modal Logic --- //
  const openPreviewModal = (content, isUnsafe = false) => {
    modalBody.textContent = content;
    if (isUnsafe) {
      modalAlert.classList.remove('hidden');
      modal.classList.add('modal-danger');
    } else {
      modalAlert.classList.add('hidden');
      modal.classList.remove('modal-danger');
    }
    modal.classList.remove('hidden');
    document.body.style.overflow = 'hidden'; // Prevent scroll
  };

  const closePreviewModal = () => {
    modal.classList.add('hidden');
    document.body.style.overflow = '';
  };

  closeModal.addEventListener('click', closePreviewModal);
  modalOverlay.addEventListener('click', closePreviewModal);

  // --- Drag and Drop & Batch Logic --- //
  dropZone.addEventListener('click', () => fileInput.click());
  dropZone.addEventListener('dragover', (e) => { e.preventDefault(); dropZone.classList.add('dragover'); });
  dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
  
  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    handleFiles(e.dataTransfer.files);
  });

  fileInput.addEventListener('change', (e) => {
    handleFiles(e.target.files);
  });

  function handleFiles(files) {
    if (!files || files.length === 0) return;
    uploadedFiles = Array.from(files);
    
    if (uploadedFiles.length > 1) {
      batchStatus.textContent = `Batch mode: ${uploadedFiles.length} files queued. Click analyze to process the first one.`;
      batchStatus.classList.remove('hidden');
    } else {
      batchStatus.classList.add('hidden');
    }
    
    loadSingleFile(uploadedFiles[0]);
  }

  function loadSingleFile(file) {
    const reader = new FileReader();
    reader.onload = (event) => {
      let content = event.target.result;
      if (file.name.endsWith('.eml')) {
        textArea.value = content.substring(0, 100000); 
      } else {
        textArea.value = content;
      }
      emailPreviewBtn.classList.remove('hidden');
    };
    reader.readAsText(file);
  }

  textArea.addEventListener('input', () => {
    if (textArea.value.trim().length > 0) {
      emailPreviewBtn.classList.remove('hidden');
    } else {
      emailPreviewBtn.classList.add('hidden');
    }
  });

  // --- Main Analysis --- //
  analyzeBtn.addEventListener('click', async () => {
    const text = textArea.value.trim();
    if (!text) {
      alert("Please enter a payload to analyze.");
      return;
    }

    currentAnalysisText = text;
    analyzeBtn.disabled = true;
    analyzeBtn.textContent = uploadedFiles.length > 1 ? `Analyzing ${currentFileIndex+1}/${uploadedFiles.length}...` : "Analyzing Payload...";
    analyzeBtn.classList.add("loader");
    resultsPanel.classList.add("hidden");

    try {
      const response = await fetch(`${API_BASE}/analyze`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'x-api-key': API_KEY 
        },
        body: JSON.stringify({ text: text })
      });

      if (!response.ok) throw new Error(`Server returned ${response.status}`);

      const data = await response.json();
      lastAnalysisResult = data;
      populateResults(data);
      resultsPanel.classList.remove("hidden");
      resultsPanel.scrollIntoView({ behavior: 'smooth' });

      // Handle batch stepping
      if (uploadedFiles.length > 1) {
        currentFileIndex++;
        if (currentFileIndex < uploadedFiles.length) {
          batchStatus.textContent = `Analyzed file ${currentFileIndex}. Ready for next file.`;
          loadSingleFile(uploadedFiles[currentFileIndex]);
          analyzeBtn.textContent = "Analyze Next File";
        } else {
          batchStatus.textContent = "Batch processing complete.";
          uploadedFiles = [];
          currentFileIndex = 0;
          analyzeBtn.textContent = "Run Threat Analysis";
        }
      }

    } catch (err) {
      console.error(err);
      alert("Failed to analyze text. Ensure backend is running.");
    } finally {
      analyzeBtn.disabled = false;
      analyzeBtn.classList.remove("loader");
      if (uploadedFiles.length <= 1) analyzeBtn.textContent = "Run Threat Analysis";
    }
  });

  function populateResults(data) {
    // 1. Threat Score
    document.getElementById('threat-score').textContent = `${data.threat_score}%`;
    const deltaEl = document.getElementById('threat-delta');
    if (data.threat_score > 70) {
      deltaEl.textContent = "CRITICAL";
      deltaEl.className = "score-delta delta-critical";
    } else if (data.threat_score > 40) {
      deltaEl.textContent = "WARNING";
      deltaEl.className = "score-delta delta-warning";
    } else {
      deltaEl.textContent = "SAFE";
      deltaEl.className = "score-delta delta-safe";
    }

    // 2. Classification
    const classEl = document.getElementById('classification');
    if (data.is_phishing) {
      classEl.innerHTML = "🚨 Malware/Phishing Detected";
      classEl.className = "score-value status-danger";
    } else {
      classEl.innerHTML = "✅ Clean";
      classEl.className = "score-value status-safe";
    }

    // 3. Legal Frameworks
    document.getElementById('legal-count').textContent = data.legal_violations.length;

    // 4. Tags & Threat Intel
    const tagsContainer = document.getElementById('risk-tags');
    tagsContainer.innerHTML = '';
    
    if (data.ti_match && data.ti_flagged_domains) {
      data.ti_flagged_domains.forEach(d => {
        const span = document.createElement('span');
        span.className = 'cyber-tag';
        span.style.background = 'rgba(255, 0, 0, 0.3)';
        span.textContent = `INTEL: Malicious Domain (${d})`;
        tagsContainer.appendChild(span);
      });
    }

    if (data.risk_tags && data.risk_tags.length > 0) {
      data.risk_tags.forEach(tag => {
        if (!tag.includes("Blacklisted Domain")) { // Skip duplicate
          const span = document.createElement('span');
          span.className = 'cyber-tag';
          span.textContent = tag;
          tagsContainer.appendChild(span);
        }
      });
    }
    
    if (tagsContainer.innerHTML === '') {
      tagsContainer.innerHTML = '<span class="info-text">No explicit risk indicators found.</span>';
    }

    // 5. XAI (SHAP Explanations)
    const xaiContainer = document.getElementById('xai-container');
    xaiContainer.innerHTML = '';
    if (data.explanations && data.explanations.shap) {
      const shapData = data.explanations.shap;
      for (const [feature, value] of Object.entries(shapData)) {
        if (Math.abs(value) > 0.01) { // Only show significant features
          const isPos = value > 0;
          const w = Math.min(Math.abs(value) * 200, 100); // scale for visual
          
          xaiContainer.innerHTML += `
            <div class="xai-row">
              <div class="xai-label">${feature}</div>
              <div class="xai-bar-bg">
                <div class="xai-bar-fill ${isPos ? 'pos' : 'neg'}" style="width: ${w}%"></div>
              </div>
              <div class="xai-val">${isPos ? '+' : ''}${value.toFixed(3)}</div>
            </div>
          `;
        }
      }
    } else {
      xaiContainer.innerHTML = '<span class="info-text">ML Explanation data unavailable for this payload.</span>';
    }

    // 6. Legal Violations
    const legalContainer = document.getElementById('legal-violations');
    legalContainer.innerHTML = '';
    if (data.legal_violations && data.legal_violations.length > 0) {
      data.legal_violations.forEach(v => {
        const title = typeof v === 'string' ? v : v.title;
        const desc = typeof v === 'string' ? "Compliance violation detected." : v.description;
        
        const div = document.createElement('div');
        div.className = 'expander';
        div.innerHTML = `
          <div class="expander-header">⚠️ ${title}</div>
          <div class="expander-body">${desc}</div>
        `;
        legalContainer.appendChild(div);
      });
    } else {
      legalContainer.innerHTML = '<div class="success-box">No specific legal compliance risks detected.</div>';
    }
  }

  // --- Safe Preview Email --- //
  emailPreviewBtn.addEventListener('click', () => {
    const text = textArea.value.trim();
    if (!text) return;
    
    const isUnsafe = lastAnalysisResult ? lastAnalysisResult.is_phishing : false;
    openPreviewModal(text, isUnsafe);
  });

  // --- Sandboxed Link Preview --- //
  document.getElementById('preview-btn').addEventListener('click', async () => {
    const url = document.getElementById('link-url').value.trim();
    if (!url) return;
    
    const previewBtn = document.getElementById('preview-btn');
    const originalText = previewBtn.textContent;
    previewBtn.textContent = "Loading...";
    previewBtn.disabled = true;

    try {
      const res = await fetch(`${API_BASE}/api/v1/preview-link?url=${encodeURIComponent(url)}`, {
        headers: { 'x-api-key': API_KEY }
      });
      const data = await res.json();
      if (data.safe_preview) {
        const previewText = `Page Title: ${data.title}\nStatus: HTTP ${data.status_code}\nURL: ${url}`;
        openPreviewModal(previewText, false);
      } else {
        openPreviewModal(`Error: ${data.error}`, false);
      }
    } catch (e) {
      openPreviewModal('Failed to fetch preview.', false);
    } finally {
      previewBtn.textContent = originalText;
      previewBtn.disabled = false;
    }
  });

  // --- Active Learning Feedback --- //
  const handleFeedback = async (isPhishingActually) => {
    try {
      await fetch(`${API_BASE}/api/v1/feedback`, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'x-api-key': API_KEY 
        },
        body: JSON.stringify({
          original_text: currentAnalysisText,
          is_phishing_actually: isPhishingActually
        })
      });
      alert('Feedback recorded. The model will use this for retraining. Thank you!');
    } catch (e) {
      alert('Failed to submit feedback.');
    }
  };

  document.getElementById('btn-feedback-fp').addEventListener('click', () => handleFeedback(false));
  document.getElementById('btn-feedback-fn').addEventListener('click', () => handleFeedback(true));
});