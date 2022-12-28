window.onload = () => {

const button = document.getElementById("upload-button");

button.addEventListener("click", () => {
    let formData = new FormData();
    let file = document.getElementById("file");
    if(file.files.length){
    formData.append("file", file.files[0]);
    fetch('/api/web/upload', { method: "POST",  body: formData })
    .then(res => {})
    .then(() => window.location.href = "/login");
    }
     else {
    alert ("no file selected")
    }
  });
}