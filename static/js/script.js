document.addEventListener("DOMContentLoaded", function () {
    const optionCards = document.querySelectorAll(".option-card");
    const forms = document.querySelectorAll(".analysis-form");

    optionCards.forEach(function (card) {
        card.addEventListener("click", function () {
            const targetId = card.getAttribute("data-target");
            optionCards.forEach(function (c) { c.classList.remove("active"); });
            card.classList.add("active");
            forms.forEach(function (form) {
                if (form.id === targetId) {
                    form.classList.remove("hidden");
                    form.scrollIntoView({ behavior: "smooth", block: "center" });
                } else {
                    form.classList.add("hidden");
                }
            });
        });
    });

    const messageTextarea = document.getElementById("message_text");
    const charCount = document.getElementById("char-count");

    if (messageTextarea && charCount) {
        messageTextarea.addEventListener("input", function () {
            charCount.textContent = messageTextarea.value.length;
        });
    }

    const dropzone = document.getElementById("dropzone");
    const fileInput = document.getElementById("file-input");
    const dropzoneContent = document.getElementById("dropzone-content");
    const imagePreview = document.getElementById("image-preview");

    if (dropzone && fileInput) {
        dropzone.addEventListener("click", function () {
            fileInput.click();
        });

        dropzone.addEventListener("dragover", function (e) {
            e.preventDefault();
            dropzone.classList.add("dragover");
        });

        dropzone.addEventListener("dragleave", function () {
            dropzone.classList.remove("dragover");
        });

        dropzone.addEventListener("drop", function (e) {
            e.preventDefault();
            dropzone.classList.remove("dragover");
            if (e.dataTransfer.files.length) {
                fileInput.files = e.dataTransfer.files;
                showImagePreview(fileInput.files[0]);
            }
        });

        fileInput.addEventListener("change", function () {
            if (fileInput.files.length) {
                showImagePreview(fileInput.files[0]);
            }
        });
    }

    function showImagePreview(file) {
        if (!file.type.startsWith("image/")) {
            return;
        }
        const reader = new FileReader();
        reader.onload = function (e) {
            imagePreview.src = e.target.result;
            imagePreview.classList.remove("hidden");
            dropzoneContent.classList.add("hidden");
        };
        reader.readAsDataURL(file);
    }

    const loadingOverlay = document.getElementById("loading-overlay");
    const analysisForms = document.querySelectorAll(".analysis-form");

    analysisForms.forEach(function (form) {
        form.addEventListener("submit", function () {
            if (loadingOverlay) {
                loadingOverlay.classList.remove("hidden");
            }
        });
    });

});
