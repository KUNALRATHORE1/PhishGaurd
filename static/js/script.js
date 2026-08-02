/* =========================================================
   PhishGuard Frontend JavaScript
   Handles: card selection, drag-and-drop upload, image preview,
   character counter, and loading spinner.
========================================================= */

document.addEventListener("DOMContentLoaded", function () {

    // ---------------------------------------------------
    // 1. Card selection -> show corresponding form
    // ---------------------------------------------------
    const optionCards = document.querySelectorAll(".option-card");
    const forms = document.querySelectorAll(".analysis-form");

    optionCards.forEach(function (card) {
        card.addEventListener("click", function () {
            const targetId = card.getAttribute("data-target");

            // Toggle active state on cards
            optionCards.forEach(function (c) { c.classList.remove("active"); });
            card.classList.add("active");

            // Show only the selected form
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

    // ---------------------------------------------------
    // 2. Character counter for text analysis
    // ---------------------------------------------------
    const messageTextarea = document.getElementById("message_text");
    const charCount = document.getElementById("char-count");

    if (messageTextarea && charCount) {
        messageTextarea.addEventListener("input", function () {
            charCount.textContent = messageTextarea.value.length;
        });
    }

    // ---------------------------------------------------
    // 3. Drag-and-drop screenshot upload + image preview
    // ---------------------------------------------------
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

    // ---------------------------------------------------
    // 4. Loading spinner on form submit
    // ---------------------------------------------------
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