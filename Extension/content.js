// content.js – nhận lệnh highlight từ popup/background
const SCAM_KEYWORDS = [
    'chuyển tiền', 'mật khẩu', 'otp', 'khóa tài khoản', 'xác minh',
    'khẩn cấp', 'ngay lập tức', 'cảnh báo', 'bị khóa', 'đăng nhập',
    'trúng thưởng đặc biệt', 'click ngay', 'hết hạn hôm nay'
];

function highlightKeywords(keywords) {
    const body = document.querySelector('.a3s');
    if (!body) return;
    // Xóa highlight cũ nếu có
    body.querySelectorAll('mark[data-spamshield]').forEach(el => {
        const parent = el.parentNode;
        parent.replaceChild(document.createTextNode(el.textContent), el);
    });
    const regex = new RegExp(`(${keywords.join('|')})`, 'gi');
    const walker = document.createTreeWalker(body, NodeFilter.SHOW_TEXT, {
        acceptNode: function(node) {
            if (node.parentNode.tagName === 'SCRIPT' || 
                node.parentNode.tagName === 'STYLE' || 
                node.parentNode.tagName === 'MARK') {
                return NodeFilter.FILTER_REJECT;
            }
            return NodeFilter.FILTER_ACCEPT;
        }
    });
    const nodesToReplace = [];
    while (walker.nextNode()) {
        const node = walker.currentNode;
        if (regex.test(node.textContent)) {
            nodesToReplace.push(node);
        }
    }
    nodesToReplace.forEach(node => {
        const fragment = document.createDocumentFragment();
        const parts = node.textContent.split(regex);
        parts.forEach(part => {
            if (regex.test(part)) {
                const mark = document.createElement('mark');
                mark.setAttribute('data-spamshield', 'true');
                mark.style.cssText = 'background:#ea4335; color:white; padding:2px 4px; border-radius:3px;';
                mark.textContent = part;
                fragment.appendChild(mark);
            } else {
                fragment.appendChild(document.createTextNode(part));
            }
        });
        node.parentNode.replaceChild(fragment, node);
    });
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'HIGHLIGHT_KEYWORDS') {
        highlightKeywords(request.keywords || SCAM_KEYWORDS);
        sendResponse({ status: 'done' });
    }
});
