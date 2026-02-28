document.addEventListener('DOMContentLoaded', function () {
    var fadingElements = document.querySelectorAll('body > :not(header):not(footer)');
    fadingElements.forEach(function (el) {
        el.classList.add('page-fade');
    });
    document.body.classList.add('page-loaded');

    document.addEventListener('click', function (e) {
        var anchor = e.target.closest('a[href]');
        if (!anchor)
            return;
        var href = anchor.getAttribute('href');
        if (!href || href.startsWith('#') || anchor.target)
            return;
        var url = new URL(anchor.href, window.location.href);
        if (url.origin !== window.location.origin)
            return;
        e.preventDefault();
        var navigate = function () {
            window.location.href = anchor.href;
        };
        document.body.classList.remove('page-loaded');
        var firstFade = fadingElements[0];
        (firstFade || document.body).addEventListener('transitionend', navigate, { once: true });
    });
});
