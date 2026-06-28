document.addEventListener('DOMContentLoaded', () => {
    const actionSection = document.getElementById('action-section');
    const loadingSection = document.getElementById('loading-section');
    const resultSection = document.getElementById('result-section');
    
    const btnStandard = document.getElementById('btn-standard');
    const btnPro = document.getElementById('btn-pro');
    const btnStop = document.getElementById('btn-stop');
    const btnBack = document.getElementById('btn-back');
    const btnWhitelist = document.getElementById('btn-whitelist');
    const btnHistory = document.getElementById('btn-history');
    const btnManageLists = document.getElementById('btn-manage-lists');

    const resultCard = document.getElementById('result-card');
    const resultTitle = document.getElementById('result-title');
    const resultScore = document.getElementById('result-score');
    
    const scoreHam = document.getElementById('score-ham');
    const scoreSpam = document.getElementById('score-spam');
    const scoreScam = document.getElementById('score-scam');
    const highlightsList = document.getElementById('highlights-list');

    const sensBtns = document.querySelectorAll('.sens-btn');
    const sensDescription = document.getElementById('sens-description');

    const resultMode = document.getElementById('result-mode');
    const feedbackSection = document.getElementById('feedback-section');
    const fbHam = document.getElementById('fb-ham');
    const fbSpam = document.getElementById('fb-spam');
    const fbScam = document.getElementById('fb-scam');
    const feedbackMsg = document.getElementById('feedback-msg');

    const SCAM_KEYWORDS = [
        'chuyển tiền', 'mật khẩu', 'otp', 'khóa tài khoản', 'xác minh',
        'khẩn cấp', 'ngay lập tức', 'cảnh báo', 'bị khóa', 'đăng nhập',
        'trúng thưởng đặc biệt', 'click ngay', 'hết hạn hôm nay'
    ];

    let currentResult = null;

    // ==========================================
    // 0. KHÔI PHỤC TRẠNG THÁI KHI MỞ POPUP
    // ==========================================
    chrome.runtime.sendMessage({ action: "GET_STATUS" }, (state) => {
        if (state) {
            if (state.scanning) {
                showLoading();
            } else if (state.error) {
                showError(state.error);
            } else if (state.result) {
                renderResult(state.result);
            } else {
                showIdle();
            }
        }
    });

    // ==========================================
    // THIẾT LẬP ĐỘ NHẠY (3 NÚT)
    // ==========================================
    const sensitivityModes = {
        relaxed:  { threshold: 0.85, desc: 'Chỉ cảnh báo khi rất chắc chắn (ít bị làm phiền)' },
        balanced: { threshold: 0.65, desc: 'Cảnh báo hầu hết email đáng ngờ (mặc định)' },
        strict:   { threshold: 0.45, desc: 'Nhạy hơn, có thể báo nhầm nhưng an toàn' }
    };

    chrome.storage.local.get(['user_bias'], (data) => {
        let bias = data.user_bias || 0;
        let threshold = 0.65 + bias;
        let currentMode = 'balanced';
        if (threshold >= 0.85) currentMode = 'relaxed';
        else if (threshold <= 0.45) currentMode = 'strict';
        
        sensBtns.forEach(btn => {
            if (btn.dataset.mode === currentMode) {
                btn.classList.add('active');
                btn.style.background = '#4285f4';
            } else {
                btn.classList.remove('active');
                btn.style.background = '#3c4043';
            }
        });
        sensDescription.textContent = sensitivityModes[currentMode].desc;
    });

    sensBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const mode = btn.dataset.mode;
            const threshold = sensitivityModes[mode].threshold;
            const bias = threshold - 0.65;
            
            chrome.storage.local.set({ user_bias: bias });
            
            sensBtns.forEach(b => {
                b.classList.remove('active');
                b.style.background = '#3c4043';
            });
            btn.classList.add('active');
            btn.style.background = '#4285f4';
            sensDescription.textContent = sensitivityModes[mode].desc;
        });
    });

    // ==========================================
    // 1. SỰ KIỆN NÚT BẤM
    // ==========================================
    btnStandard.addEventListener('click', () => startScanning("standard"));
    btnPro.addEventListener('click', () => startScanning("pro"));
    
    btnStop.addEventListener('click', () => {
        chrome.runtime.sendMessage({ action: "STOP_SCAN" });
        showIdle();
    });

    btnBack.addEventListener('click', () => {
        chrome.runtime.sendMessage({ action: "RESET_STATE" });
        showIdle();
    });
    
    btnWhitelist.addEventListener('click', () => {
        chrome.runtime.sendMessage({ action: "TRUST_CURRENT_SENDER" });
        alert("Đã thêm địa chỉ này vào danh sách Whitelist an toàn!");
        chrome.runtime.sendMessage({ action: "RESET_STATE" });
        showIdle();
    });

    fbHam.addEventListener('click', () => sendFeedback('ham'));
    fbSpam.addEventListener('click', () => sendFeedback('spam'));
    fbScam.addEventListener('click', () => sendFeedback('scam'));

    function sendFeedback(label) {
        if (!currentResult) return;
        chrome.runtime.sendMessage({
            action: "USER_FEEDBACK",
            label: label,
            originalResult: currentResult
        });
        feedbackMsg.textContent = `✅ Đã gửi phản hồi: ${label.toUpperCase()}`;
        fbHam.disabled = true;
        fbSpam.disabled = true;
        fbScam.disabled = true;
        setTimeout(() => {
            feedbackMsg.textContent = '';
        }, 2000);
    }

    if (btnHistory) {
        btnHistory.addEventListener('click', () => {
            chrome.tabs.create({ url: chrome.runtime.getURL('history.html') });
        });
    }

    if (btnManageLists) {
        btnManageLists.addEventListener('click', () => {
            chrome.tabs.create({ url: chrome.runtime.getURL('whitelist.html') });
        });
    }

    function startScanning(mode) {
        showLoading();
        
        chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
            if (!tabs || tabs.length === 0) {
                showError("Vui lòng mở một trang Email để quét!");
                return;
            }
            
            const activeTabId = tabs[0].id;
            
            chrome.runtime.sendMessage({ action: "START_SCAN", mode: mode, tabId: activeTabId }, (response) => {
                if (chrome.runtime.lastError) {
                    chrome.tabs.sendMessage(activeTabId, { action: "EXTRACT_AND_SCAN", mode: mode }, (res) => {
                        if (chrome.runtime.lastError) {
                            showError("Vui lòng tải lại trang Email (F5) và thử lại!");
                        }
                    });
                }
            });
        });
    }

    // ==========================================
    // 2. LẮNG NGHE KẾT QUẢ TỪ BACKGROUND
    // ==========================================
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.action === "SCAN_COMPLETE") {
            renderResult(request.result);
        } else if (request.action === "SCAN_FAILED") {
            showError(request.error);
        }
    });

    // ==========================================
    // 3. RENDER GIAO DIỆN
    // ==========================================
    function clearError() {
        const errDiv = document.getElementById('error-display');
        if (errDiv) errDiv.remove();
    }

    function showIdle() {
        actionSection.style.display = 'block';
        loadingSection.style.display = 'none';
        resultSection.style.display = 'none';
        clearError();
        currentResult = null;
        feedbackSection.style.display = 'none';
        fbHam.disabled = false;
        fbSpam.disabled = false;
        fbScam.disabled = false;
        feedbackMsg.textContent = '';
    }

    function showLoading() {
        actionSection.style.display = 'none';
        loadingSection.style.display = 'block';
        resultSection.style.display = 'none';
        clearError();
    }

    function showError(msg) {
        actionSection.style.display = 'block';
        loadingSection.style.display = 'none';
        resultSection.style.display = 'none';
        clearError(); 

        const errDiv = document.createElement('div');
        errDiv.id = 'error-display';
        errDiv.style.backgroundColor = '#2a1a1b';
        errDiv.style.color = '#ea4335';
        errDiv.style.padding = '10px';
        errDiv.style.borderRadius = '6px';
        errDiv.style.border = '1px solid #ea4335';
        errDiv.style.marginBottom = '15px';
        errDiv.style.fontSize = '12px';
        errDiv.style.textAlign = 'center';
        errDiv.innerText = "⚠️ " + msg;

        actionSection.insertBefore(errDiv, actionSection.firstChild);
    }

    function renderResult(data) {
        actionSection.style.display = 'none';
        loadingSection.style.display = 'none';
        resultSection.style.display = 'block';

        const prediction = data.prediction || 'ham';
        const details = data.details || { ham: 0, spam: 0, scam: 0 };
        const highlights = data.highlights || [];
        const mainProb = (data.probability * 100).toFixed(1);
        const mode = data.mode || 'standard';

        currentResult = data;

        const rowSpam = scoreSpam.parentElement;
        if (mode === 'standard') {
            rowSpam.style.display = 'none'; 
        } else {
            rowSpam.style.display = 'block'; 
        }

        if (resultMode) {
            if (mode === 'standard') {
                resultMode.innerText = '🚀 FastText (Standard)';
                resultMode.style.backgroundColor = '#0F3460';
                resultMode.style.color = '#F4D03F';
            } else {
                resultMode.innerText = '🧠 ViBERTa + Groq (Pro)';
                resultMode.style.backgroundColor = '#2E4053';
                resultMode.style.color = '#FFB085';
            }
        }

        if (prediction === 'ham') {
            resultCard.style.borderColor = '#34a853'; 
            resultCard.style.backgroundColor = '#1d2a1f';
            resultTitle.style.color = '#34a853';
            resultTitle.innerText = '✅ AN TOÀN';
            resultScore.innerText = `${mainProb}%`;
        } else if (prediction === 'spam') {
            resultCard.style.borderColor = '#fbbc04'; 
            resultCard.style.backgroundColor = '#2b281c';
            resultTitle.style.color = '#fbbc04';
            resultTitle.innerText = '📢 QUẢNG CÁO';
            resultScore.innerText = `${mainProb}%`;
        } else if (prediction === 'suspicious') {
            resultCard.style.borderColor = '#fbbc04'; 
            resultCard.style.backgroundColor = '#2b281c';
            resultTitle.style.color = '#fbbc04';
            resultTitle.innerText = '⚠️ ĐÁNG NGỜ';
            resultScore.innerText = `${mainProb}%`;
        } else if (prediction === 'scam') {
            resultCard.style.borderColor = '#ea4335'; 
            resultCard.style.backgroundColor = '#2a1a1b';
            resultTitle.style.color = '#ea4335';
            resultTitle.innerText = '🚨 CẢNH BÁO LỪA ĐẢO';
            resultScore.innerText = `${mainProb}%`;
        }

        scoreHam.innerText = `${(details.ham * 100).toFixed(1)}%`;
        scoreSpam.innerText = `${(details.spam * 100).toFixed(1)}%`;
        scoreScam.innerText = `${(details.scam * 100).toFixed(1)}%`;

        highlightsList.innerHTML = '';
        if (highlights.length > 0) {
            highlights.forEach(item => {
                const li = document.createElement('li');
                li.innerText = item;
                if (item.includes('🧠 AI phân tích')) {
                    li.classList.add('llama-insight');
                }
                highlightsList.appendChild(li);
            });
        } else {
            highlightsList.innerHTML = '<li style="color:gray; list-style:none;">Không phát hiện từ khóa nguy hiểm.</li>';
        }

        feedbackSection.style.display = 'block';
        fbHam.disabled = false;
        fbSpam.disabled = false;
        fbScam.disabled = false;
        feedbackMsg.textContent = '';

        // Gửi lệnh highlight từ khóa scam đến content script
        chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
            if (tabs[0]) {
                chrome.tabs.sendMessage(tabs[0].id, {
                    action: "HIGHLIGHT_KEYWORDS",
                    keywords: SCAM_KEYWORDS
                }).catch(() => {});
            }
        });
    }
});
