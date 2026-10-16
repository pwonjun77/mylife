import DOMPurify from 'dompurify';

export function showComment(container, commentHtml) {
  container.innerHTML = DOMPurify.sanitize(commentHtml);
}

export function showPreview(container) {
  const html = decodeURIComponent(location.hash.slice(1));
  container.innerHTML = html;
}
