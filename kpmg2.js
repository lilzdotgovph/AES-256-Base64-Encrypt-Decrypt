function def(){
 var text = document.createElement("h1");
 text.textContent = "THIS PAGE HAS BEEN MODIFIED!";
 var image = document.createElement("img");
 image.src = "https://upload.wikimedia.org/wikipedia/commons/thumb/d/dc/Logo_of_KPMG.svg/1200px-Logo_of_KPMG.svg.png";
 document.body.appendChild(text);
 document.body.appendChild(image);
}

def();
