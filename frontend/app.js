document.addEventListener('DOMContentLoaded', () => {
  const dropZone = document.getElementById('drop-zone');
  const fileInput = document.getElementById('file-input');
  const textArea = document.getElementById('email-text');
  const analyzeBtn = document.getElementById('analyze-btn');
  const resultsPanel = document.getElementById('results-panel');

  // FASTAPI URL
  // Note: For local docker, the browser calls localhost directly
  const API_URL = 'http://localhost:8000/analyze';

  // --- Drag and Drop Logic --- //
  dropZone.addEventListener('click', () => fileInput.click());

  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });

  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
  });

  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFile(e.dataTransfer.files[0]);
    }
  });

  fileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFile(e.target.files[0]);
    }
  });

  function handleFile(file) {
    const reader = new FileReader();
    reader.onload = (event) => {
      let content = event.target.result;

      if (file.name.endsWith('.eml')) {
        // Very basic inline parsing for generic EML display
        // Since we are in the browser, we use regex to extract key fields easily
        const subjectMatch = content.match(/^Subject:\s*(.*)$/im);
        const fromMatch = content.match(/^From:\s*(.*)$/im);

        let parsed = "";
        if (subjectMatch) parsed += `Subject: ${subjectMatch[1]}\n`;
        if (fromMatch) parsed += `From: ${fromMatch[1]}\n\n`;

        // Find boundary to extract plain text if multipart
        // Alternatively, just dump the whole text since the backend handles raw text
        // Dumping the whole text is safer to preserve all risk indicators
        parsed += "\n[Raw Source Below]\n\n" + content;

        textArea.value = parsed.substring(0, 5000); // truncate if massive
      } else {
        textArea.value = content;
      }
    };
    reader.readAsText(file);
  }

  // --- API Interaction --- //
  analyzeBtn.addEventListener('click', async () => {
    const text = textArea.value.trim();
    if (!text) {
      alert("Please enter a payload to analyze.");
      return;
    }

    // UI Loading state
    analyzeBtn.disabled = true;
    analyzeBtn.textContent = "Analyzing Payload...";
    analyzeBtn.classList.add("loader");
    resultsPanel.classList.add("hidden");

    try {
      const response = await fetch(API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text: text })
      });

      if (!response.ok) {
        throw new Error(`Server returned ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      populateResults(data);
      resultsPanel.classList.remove("hidden");

      // Scroll to results
      resultsPanel.scrollIntoView({ behavior: 'smooth' });

    } catch (err) {
      console.error(err);
      alert("Failed to analyze text. Ensure backend is running at " + API_URL);
    } finally {
      // Revert loading state
      analyzeBtn.disabled = false;
      analyzeBtn.textContent = "Run Threat Analysis";
      analyzeBtn.classList.remove("loader");
    }
  });

  function populateResults(data) {
    // 1. Threat Score
    const scoreEl = document.getElementById('threat-score');
    const deltaEl = document.getElementById('threat-delta');

    scoreEl.textContent = `${data.threat_score}%`;

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

    // 3. Legal Frameworks Tripped
    const legalCountEl = document.getElementById('legal-count');
    legalCountEl.textContent = data.legal_violations.length;

    // 4. Tags
    const tagsContainer = document.getElementById('risk-tags');
    tagsContainer.innerHTML = '';
    if (data.risk_tags && data.risk_tags.length > 0) {
      data.risk_tags.forEach(tag => {
        const span = document.createElement('span');
        span.className = 'cyber-tag';
        span.textContent = tag;
        tagsContainer.appendChild(span);
      });
    } else {
      tagsContainer.innerHTML = '<span class="info-text">No explicit risk indicators found based on the rules engine.</span>';
    }

    // 5. Legal Expanders
    const legalContainer = document.getElementById('legal-violations');
    legalContainer.innerHTML = '';
    if (data.legal_violations && data.legal_violations.length > 0) {
      data.legal_violations.forEach(violation => {
        const div = document.createElement('div');
        div.className = 'expander';

        let desc = "A customized compliance violation was detected.";
        if (violation.includes("66C")) {
          desc = "<strong>Section 66C of the Information Technology Act, 2000</strong> deals with punishment for identity theft. The payload indicates attempts to harvest passwords or spoof identities.";
        } else if (violation.includes("66D")) {
          desc = "<strong>Section 66D of the Information Technology Act, 2000</strong> deals with punishment for cheating by personation by using a computer resource. The payload involves impersonation, often for financial fraud.";
        } else if (violation.includes("DPDP")) {
          desc = "<strong>Digital Personal Data Protection Act, 2023</strong> relates to the processing of digital personal data. The payload demonstrates risks to data privacy (e.g. asking for SSN, Date of Birth).";
        }

        div.innerHTML = `
          <div class="expander-header">⚠️ ${violation}</div>
          <div class="expander-body">${desc}</div>
        `;
        legalContainer.appendChild(div);
      });
    } else {
      legalContainer.innerHTML = '<div class="success-box">No specific legal compliance risks detected in this payload.</div>';
    }
  }
});
