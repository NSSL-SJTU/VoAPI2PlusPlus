() => {
    const targets = [];
    const all = document.querySelectorAll('*');
    const blacklist = ['delete', 'remove', 'logout', 'Log out', 'sign out', '删除', '移除', '登出', '退出'];

    all.forEach(el => {
        const style = window.getComputedStyle(el);
        const rect = el.getBoundingClientRect();

        if (rect.width < 5 || rect.height < 5 || style.display === 'none' || style.visibility === 'hidden') return;

        const isPointer = style.cursor === 'pointer';
        const isTag = ['BUTTON', 'A', 'INPUT'].includes(el.tagName);

        if (isPointer || isTag) {
            let text = (el.innerText || el.value || el.getAttribute('aria-label') || '').trim();
            if (blacklist.some(kw => text.toLowerCase().includes(kw))) return;

            let score = 0;
            if (el.className.includes('row') || el.className.includes('card')) score += 10;
            if (text === '') score -= 5;

            targets.push({
                tag: el.tagName,
                text: text.substring(0, 50),
                x: rect.x + rect.width / 2,
                y: rect.y + rect.height / 2,
                score: score
            });
        }
    });
    return targets.sort((a, b) => b.score - a.score);
}
