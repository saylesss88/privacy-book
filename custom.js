document.addEventListener('DOMContentLoaded', function () {
  var button = document.createElement('a');
  button.className = "top-link";
  button.href = "#top";
  button.innerHTML = "↑";
  button.style.display = "none";
  document.body.appendChild(button);

  window.addEventListener('scroll', function () {
    button.style.display = (window.scrollY > 200) ? "inline-flex" : "none";
  });
});
