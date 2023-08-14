const collapsibleContainers = document.querySelectorAll('.collapsible-container');
collapsibleContainers.forEach(container => {
    const checkbox = container.querySelector('.collapsible-checkbox');
    const collapsibleButton = container.querySelector('.collapsible');
	const content = container.querySelector('.content');

    collapsibleButton.addEventListener('click', () => {
        content.classList.toggle('expanded');
		collapsibleButton.classList.toggle('expanded');
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

        if (searchTerm.length === 0) {
            row.style.display = "table-row";
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
		
		if(found === true) {
			row.style.display = "table-row";
		}
		else {
			row.style.display = "none";
		}
    });
}

let goTopButton = document.querySelector(".go-top-button");
window.onscroll = function() { scrollFunction() };

function scrollFunction() {
  if (document.body.scrollTop > 20 || document.documentElement.scrollTop > 20) {
    goTopButton.style.display = "block";
  } else {
    goTopButton.style.display = "none";
  }
}

function topFunction() {
  document.body.scrollTop = 0; // For Safari
  document.documentElement.scrollTop = 0; // For Chrome, Firefox, IE and Opera
}

function copyNbiData(row) {
  const protocolCell = findProtocolCell(row);
  
  const dataCells = Array.from(row.querySelectorAll('td'));
      const headers = Array.from(tableHeader.querySelectorAll('th'));

      const nbiData = {};
      headers.forEach((header, index) => {
        const key = header.textContent.trim();
        const value = dataCells[index].textContent.trim();
        nbiData[key] = value;
      });

      const fieldMap = {};

      Object.keys(nbiData).forEach(key => {
        const lines = nbiData[key].split('\n');
        const keyMap = {};

        lines.forEach(line => {
			const parts = line.split(':');
			if (parts.length > 1) {
				const subKey = parts.shift().trim();
				const subValue = parts.join(':').trim();
				
				if (subKey && subValue) {
					keyMap[subKey] = subValue;
				}
			}
		});

        fieldMap[key] = keyMap;
      });
	  
		let copiedText = '';

  if (protocolCell) {
    const protocolText = protocolCell.textContent.trim().toLowerCase();

    if (protocolText === 'http') {
      let url = '';
      if (fieldMap['Additional Information']['SSL encrypted'] === 'Yes') {
        url = `https[:]//${fieldMap['NBI']['Host']}:${fieldMap['Additional Information']['Destination port']}${fieldMap['NBI']['uri']}`;
      } else {
        url = `http[:]//${fieldMap['NBI']['Host']}:${fieldMap['Additional Information']['Destination port']}${fieldMap['NBI']['uri']}`;
      }

      copiedText += '## URL\n\n';
      copiedText += `*   \`${url}\``;
    }
	
	else if (protocolText === 'dns') {
		copiedText += '## DNS\n\n';
		copiedText += `*   \`${fieldMap['NBI']['query_name']}\``;
	}
	
	// ftp, smtp, tftp, pop, irc, raw and unknown protocols come in connections.
	else {
		copiedText += '## Connections\n\n';
		copiedText += `*   \`${protocolText}[:]//${fieldMap['Additional Information']['Destination IP']}:${fieldMap['Additional Information']['Destination port']}\``;
	}
	
	/*	if (protocolText === 'pop/irc') {}//dk as of now
	
    if (protocolText === 'icmp') {}//dk as of now
	*/
	
	Object.entries(fieldMap).forEach(([key, value]) => {
        if (key !== 'Select' && key !== 'Actions') {
			 Object.entries(value).forEach(([key1, value1]) => {
				copiedText += `\n    * ${key1}: \`${value1}\``;
			 })
        }
		});
      copyToClipboard(copiedText);
  }
  return copiedText;
}


function findProtocolCell(row) {
  let parent = row.parentNode;
  while (parent) {
    const protocolCell = parent.querySelector('.collapsible');
    if (protocolCell) {
      return protocolCell;
    }
    parent = parent.parentNode;
  }
  return null;
}

function copySelectedNbis() {
  const checkboxes = document.querySelectorAll('input[name="nbi-checkbox"]:checked');
  const selectedData = [];
  const categoricalSelectedData = [["## Connections"], ["## DNS"], ["## URL"]]; 

  checkboxes.forEach((checkbox) => {
    const row = checkbox.closest('tr');
    const copiedText = copyNbiData(row);
    
    if (copiedText.startsWith("## Connections")) {
      categoricalSelectedData[0].push(copiedText.substring(copiedText.indexOf('\n\n') + 2));
    } else if (copiedText.startsWith("## DNS")) {
      categoricalSelectedData[1].push(copiedText.substring(copiedText.indexOf('\n\n') + 2));
    } else if (copiedText.startsWith("## URL")) {
      categoricalSelectedData[2].push(copiedText.substring(copiedText.indexOf('\n\n') + 2));
    }
    
    selectedData.push(copiedText);
  });
  
  const copiedText = categoricalSelectedData
    .map((sectionData) => sectionData.join('\n\n'))
    .filter((sectionText) => sectionText.length > 0)
    .join('\n\n\n');
  
  copyToClipboard(copiedText);
}

function copyAllTables() {
  const tables = document.querySelectorAll("table");
  const categoricalSelectedData = [["## Connections"], ["## DNS"], ["## URL"]];

  tables.forEach((table) => {
    const rows = table.querySelectorAll("tr");
    rows.forEach((row) => {
      const cells = row.querySelectorAll("td");
      if (cells.length > 0) {
        const copiedText = copyNbiData(row);
        if (copiedText.startsWith("## Connections")) {
          categoricalSelectedData[0].push(copiedText.substring(copiedText.indexOf('\n\n') + 2));
        } else if (copiedText.startsWith("## DNS")) {
          categoricalSelectedData[1].push(copiedText.substring(copiedText.indexOf('\n\n') + 2));
        } else if (copiedText.startsWith("## URL")) {
          categoricalSelectedData[2].push(copiedText.substring(copiedText.indexOf('\n\n') + 2));
        }
      }
    });
  });

  const copiedText = categoricalSelectedData
    .map((sectionData) => sectionData.join('\n\n'))
    .filter((sectionText) => sectionText.length > 0)
    .join('\n\n\n');

  copyToClipboard(copiedText);
}

function copyFilteredNbis() {
const tables = document.querySelectorAll("table");
  const categoricalSelectedData = [["## Connections"], ["## DNS"], ["## URL"]];

  tables.forEach((table) => {
    const rows = table.querySelectorAll("tr");
    rows.forEach((row) => {
      const cells = row.querySelectorAll("td");
      if (cells.length > 0 && row.style.display !== "none") {
        const copiedText = copyNbiData(row);
        if (copiedText.startsWith("## Connections")) {
          categoricalSelectedData[0].push(copiedText.substring(copiedText.indexOf('\n\n') + 2));
        } else if (copiedText.startsWith("## DNS")) {
          categoricalSelectedData[1].push(copiedText.substring(copiedText.indexOf('\n\n') + 2));
        } else if (copiedText.startsWith("## URL")) {
          categoricalSelectedData[2].push(copiedText.substring(copiedText.indexOf('\n\n') + 2));
        }
      }
    });
  });

  const copiedText = categoricalSelectedData
    .map((sectionData) => sectionData.join('\n\n'))
    .filter((sectionText) => sectionText.length > 0)
    .join('\n\n\n');

  copyToClipboard(copiedText);
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

const disclaimerButton = document.querySelector('.disclaimer-button');
const disclaimerPopup = document.querySelector('.disclaimer-popup');
const popupClose = document.querySelector('.popup-close');

disclaimerButton.addEventListener('click', () => {
    disclaimerPopup.style.display = 'flex';
});

popupClose.addEventListener('click', () => {
    disclaimerPopup.style.display = 'none';
});
