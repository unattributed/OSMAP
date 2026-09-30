"""Prepared test-only browser expression for computed flat-colour text auditing.

This does not assert accessibility conformance. Gradient backgrounds, OS native
controls, icons and human assistive-technology use need separate review.
"""

TEXT_AUDIT = r"""() => {
    const rgba = value => {
        const m = value.match(/^rgba?\(([^)]+)\)$/);
        if (!m) return null;
        const p = m[1].split(',').map(Number);
        return [p[0], p[1], p[2], p.length > 3 ? p[3] : 1];
    };
    const blend = (fg, bg) => [0,1,2].map(i => fg[i]*fg[3]+bg[i]*(1-fg[3])).concat([1]);
    const luminance = rgb => rgb.slice(0,3).map(v => {
        v/=255; return v<=.04045 ? v/12.92 : Math.pow((v+.055)/1.055,2.4);
    }).reduce((s,v,i)=>s+v*[.2126,.7152,.0722][i],0);
    const ratio = (a,b) => {
        const x=luminance(a),y=luminance(b); return (Math.max(x,y)+.05)/(Math.min(x,y)+.05);
    };
    const results = new Map();
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    while(walker.nextNode()) {
        const node=walker.currentNode, parent=node.parentElement;
        if (!node.textContent.trim() || !parent || ['STYLE','SCRIPT'].includes(parent.tagName)
            || parent.closest('[disabled],.sr-only')) continue;
        const range=document.createRange(); range.selectNodeContents(node);
        const rect=range.getBoundingClientRect();
        const style=getComputedStyle(parent);
        if (rect.width<1 || rect.height<1 || style.visibility!=='visible') continue;
        const chain=[]; let gradient=false, translucent=false;
        for(let p=parent;p;p=p.parentElement){
            const s=getComputedStyle(p);
            gradient ||= s.backgroundImage!=='none';
            translucent ||= Number(s.opacity)<1;
            const c=rgba(s.backgroundColor); if(c) { chain.push(c); if(c[3]===1) break; }
        }
        let bg=[255,255,255,1]; for(const c of chain.reverse()) bg=blend(c,bg);
        const fg=rgba(style.color); if(!fg) continue;
        const contrast=ratio(blend(fg,bg),bg);
        const size=parseFloat(style.fontSize),weight=Number(style.fontWeight);
        const minimum=size>=24 || size>=18.66 && weight>=700 ? 3 : 4.5;
        const key=[style.color,bg.slice(0,3).join(','),minimum,gradient,translucent].join('|');
        if(!results.has(key)) results.set(key,{foreground:style.color,background:bg.slice(0,3),
            contrast:Number(contrast.toFixed(3)),minimum,gradient,translucent,
            sample:node.textContent.trim().slice(0,80),tag:parent.tagName});
    }
    const root=getComputedStyle(document.documentElement);
    const token=name=>{
        const value=root.getPropertyValue(name).trim();
        if (/^#[a-f0-9]{6}$/i.test(value)) return [1,3,5].map(i=>parseInt(value.slice(i,i+2),16)).concat([1]);
        return rgba(value);
    };
    const meaningful_ui=[];
    for(const [foreground,background] of [
        ['--line-strong','--panel'],['--line-strong','--panel-soft'],
        ['--focus','--panel'],['--focus','--bg'],['--focus','--selected'],
        ['--muted','--panel'],['--link','--selected'],
    ]) {
        const fg=token(foreground), bg=token(background);
        if(fg&&bg) meaningful_ui.push({foreground,background,contrast:Number(ratio(fg,bg).toFixed(3)),minimum:3});
    }
    const pairs=Array.from(results.values());
    return {pairs,meaningful_ui,ui_failures:meaningful_ui.filter(p=>p.contrast+0.005<p.minimum),failures:pairs.filter(p=>!p.gradient&&!p.translucent&&p.contrast+0.005<p.minimum),
        needs_visual_review:pairs.filter(p=>p.gradient||p.translucent)};
}"""
