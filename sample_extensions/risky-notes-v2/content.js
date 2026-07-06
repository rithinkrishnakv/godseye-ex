window.addEventListener("message", function (event) {
  document.getElementById("notes").innerHTML = event.data.html;
});
