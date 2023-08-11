const collapsibleContainers = document.querySelectorAll('.collapsible-container');
collapsibleContainers.forEach(container => {
    const checkbox = container.querySelector('.collapsible-checkbox');
    const collapsibleButton = container.querySelector('.collapsible');
	const content = container.querySelector('.content');

    collapsibleButton.addEventListener('click', () => {
        content.classList.toggle('expanded');
    });

    checkbox.addEventListener('change', () => {
        const nestedCheckboxes = content.querySelectorAll('.nbi-checkbox');
        nestedCheckboxes.forEach(nestedCheckbox => {
            nestedCheckbox.checked = checkbox.checked;
        });
    });
});



const tableRows = document.querySelectorAll(".table-container table tr");
const tableHeader = document.querySelector(".table-container table tr:first-child");
const searchButton = document.getElementById("searchButton");
const searchInput = document.getElementById("searchInput");

searchButton.addEventListener("click", () => {
    performSearch();
});

searchInput.addEventListener("input", () => {
    performSearch();
});

const collapsibleCheckboxes = document.querySelectorAll(".collapsible-checkbox");
collapsibleCheckboxes.forEach((checkbox) => {
    checkbox.addEventListener("click", handleCollapsibleCheckboxClick);
});

function handleCollapsibleCheckboxClick(event) {
    const parentContainer = event.target.closest(".collapsible-container");
    const nestedCheckboxes = parentContainer.querySelectorAll("tr[data-selectable] input[type='checkbox']");
    const isChecked = event.target.checked;

    nestedCheckboxes.forEach((nestedCheckbox) => {
        nestedCheckbox.checked = isChecked;
    });
}


function performSearch() {
    const searchTerm = searchInput.value.toLowerCase();
    let headerRowDisplayed = false;

    tableRows.forEach((row, index) => {
        if (index === 0) {
            tableHeader.style.display = searchTerm.length === 0 || headerRowDisplayed ? "table-row" : "none";
            headerRowDisplayed = true;
            return;
        }

        const dataCells = row.querySelectorAll("ul.nested li");
        let found = false;
        dataCells.forEach((cell) => {
            if (cell.textContent.toLowerCase().includes(searchTerm)) {
                found = true;
            }
        });

        const collapsibleContent = row.querySelector(".content");
        if (collapsibleContent && collapsibleContent.textContent.toLowerCase().includes(searchTerm)) {
            found = true;
        }

        row.style.display = found ? "table-row" : "none";
    });
}

const goTopButton = document.querySelector(".go-top-button");
        const goBottomButton = document.querySelector(".go-bottom-button");

        goTopButton.addEventListener("click", () => {
            window.scrollTo({ top: 0, behavior: "smooth" });
        });

        goBottomButton.addEventListener("click", () => {
            const tableContainer = document.querySelector(".table-container");
            tableContainer.scrollTo({ top: tableContainer.scrollHeight, behavior: "smooth" });
        });

        window.addEventListener("scroll", () => {
            const tableContainer = document.querySelector(".table-container");
            const scrollTop = tableContainer.scrollTop;
            const scrollHeight = tableContainer.scrollHeight;
            const clientHeight = tableContainer.clientHeight;
            const showScrollThreshold = 300;

            if (scrollTop > showScrollThreshold) {
                goTopButton.style.display = "block";
            } else {
                goTopButton.style.display = "none";
            }

            if (scrollHeight - scrollTop - clientHeight > showScrollThreshold) {
                goBottomButton.style.display = "block";
            } else {
                goBottomButton.style.display = "none";
            }
        });

  function copyAllTables() {
            const tables = document.querySelectorAll("table");
            let data = "";

            for (let i = 0; i < tables.length; i++) {
                const rows = tables[i].querySelectorAll("tr");
                for (let j = 0; j < rows.length; j++) {
                    const cells = rows[j].querySelectorAll("th, td");
                    let rowData = "";
                    for (let k = 0; k < cells.length; k++) {
                      rowData += cells[k].innerText.trim() + " ";
                    }
                    data += rowData.trim() + "\n\n";
                }
            }

            const textarea = document.createElement("textarea");
            textarea.value = data;
            document.body.appendChild(textarea);

            textarea.select();
            if (document.execCommand("copy")) {
				const popup = button.nextElementSibling;
				popup.style.display = 'block';

				setTimeout(() => {
					popup.style.display = 'none';
				}, 2000);
            } else {
                alert("Failed to copy table data. You can manually copy it.");
            }

            document.body.removeChild(textarea);
        }
		
function copyNbiData(button) {
  const row = button.closest('tr');
  const rowData = Array.from(row.querySelectorAll('td, th')).map((cell) => cell.innerText);
  const copiedText = rowData.slice(0, -1).join('\t').trim();
  copyToClipboard(copiedText);
  
  const popup = button.nextElementSibling;
  popup.style.display = 'block';

  setTimeout(() => {
    popup.style.display = 'none';
  }, 2000);
}

function copySelectedNbis() {
  const checkboxes = document.querySelectorAll('input[name="nbi-checkbox"]:checked');
  const selectedData = [];

  checkboxes.forEach((checkbox) => {
    const row = checkbox.closest('tr');
    const rowData = Array.from(row.querySelectorAll('td, th')).map((cell) => cell.innerText);
    selectedData.push(rowData.slice(0, -1).join('\t').trim());
  });

  const copiedText = selectedData.join('\n'); 
  copyToClipboard(copiedText);
  
  const popup = button.nextElementSibling;
  popup.style.display = 'block';

  setTimeout(() => {
    popup.style.display = 'none';
  }, 2000);
}

function copyToClipboard(text) {
  const textArea = document.createElement('textarea');
  textArea.value = text;
  document.body.appendChild(textArea);
  textArea.select();
  document.execCommand('copy');
  document.body.removeChild(textArea);
}

function toggleCheckbox(event) {
  if (event.target.tagName === 'INPUT') {
    return;
  }

  const checkbox = event.currentTarget.querySelector('input[type="checkbox"]');
  checkbox.checked = !checkbox.checked;
}

const selectableRows = document.querySelectorAll('tr[data-selectable]');
selectableRows.forEach(row => {
  row.addEventListener('click', toggleCheckbox);
});

