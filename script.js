document.addEventListener("DOMContentLoaded", () => {
  // DOM Elements
  const scanForm = document.getElementById("scan-form")
  const progressAbortBtn = document.getElementById("progress-abort-btn")
  const terminalOutput = document.getElementById("terminal-output")
  const progressOverlay = document.getElementById("progress-overlay")
  const progressBar = document.getElementById("scan-progress-bar")
  const progressStatus = document.getElementById("progress-status")
  const resultsContainer = document.getElementById("results-container")
  const clearResultsBtn = document.getElementById("clear-results")
  const downloadReportBtn = document.getElementById("download-report")
  const tabButtons = document.querySelectorAll(".tab-btn")
  const tabPanes = document.querySelectorAll(".tab-pane")

  // Stage elements
  const stageInit = document.getElementById("stage-init")
  const stagePortScan = document.getElementById("stage-port-scan")
  const stageServiceScan = document.getElementById("stage-service-scan")
  const stageVulnScan = document.getElementById("stage-vuln-scan")
  const stageReport = document.getElementById("stage-report")

  // Info elements
  const infoTarget = document.getElementById("info-target")
  const infoStartTime = document.getElementById("info-start-time")
  const infoDuration = document.getElementById("info-duration")
  const infoOpenPorts = document.getElementById("info-open-ports")

  // Table elements
  const portsTable = document.getElementById("ports-table").querySelector("tbody")
  const vulnsContainer = document.getElementById("vulns-container")
  const rawOutput = document.getElementById("raw-output")

  // Variables
  let scanInProgress = false
  let scanAborted = false
  let scanEventSource = null
  let currentScanId = null
  let scanResults = null
  let selectedFormat = "html" // Default format

  // First check server health
  checkServerHealth()

  // Terminal functionality
  function addTerminalLine(text, className = "") {
    const line = document.createElement("div")
    line.className = `terminal-line ${className}`
    line.textContent = text
    terminalOutput.appendChild(line)
    terminalOutput.scrollTop = terminalOutput.scrollHeight

    // Add prompt after each command
    if (className === "terminal-command") {
      const prompt = document.createElement("div")
      prompt.className = "terminal-line terminal-prompt"
      prompt.textContent = "$"
      terminalOutput.appendChild(prompt)
      terminalOutput.scrollTop = terminalOutput.scrollHeight
    }
  }

  // Check if server is running
  function checkServerHealth() {
    fetch("/api/health")
      .then((response) => {
        if (response.ok) {
          addTerminalLine("Server is running. Ready to scan.", "terminal-success")
        } else {
          addTerminalLine(
            "Warning: Server health check failed. There might be connectivity issues.",
            "terminal-warning",
          )
        }
      })
      .catch((error) => {
        addTerminalLine("Error: Cannot connect to server. Make sure the server is running.", "terminal-error")
        console.error("Server health check failed:", error)
      })
  }

  // Tab functionality
  tabButtons.forEach((button) => {
    button.addEventListener("click", () => {
      // Remove active class from all buttons and panes
      tabButtons.forEach((btn) => btn.classList.remove("active"))
      tabPanes.forEach((pane) => pane.classList.remove("active"))

      // Add active class to clicked button and corresponding pane
      button.classList.add("active")
      const tabId = button.getAttribute("data-tab")
      document.getElementById(tabId).classList.add("active")
    })
  })

  // Form submission
  scanForm.addEventListener("submit", (e) => {
    e.preventDefault()

    if (scanInProgress) {
      return
    }

    // Get form data
    const formData = new FormData(scanForm)
    const target = formData.get("target")
    const ports = formData.get("ports")
    const threads = formData.get("threads")
    const timeout = formData.get("timeout")
    const format = formData.get("format")

    // Store the selected format
    selectedFormat = format

    // Validate input
    if (!target) {
      addTerminalLine("Error: Target is required", "terminal-error")
      return
    }

    // Add command to terminal
    addTerminalLine(`scan ${target} -p ${ports} -t ${threads} -T ${timeout} -f ${format}`, "terminal-command")

    // Start scan
    startScan(target, ports, threads, timeout, format)
  })

  // Stop scan
  /*
  stopScanBtn.addEventListener("click", () => {
    if (!scanInProgress) {
      return
    }

    abortScan()
  })
  */

  // Add event listener for the progress abort button
  progressAbortBtn.addEventListener("click", () => {
    if (!scanInProgress) {
      return
    }
    abortScan()
  })

  // Clear results
  clearResultsBtn.addEventListener("click", () => {
    resultsContainer.classList.add("hidden")
    scanResults = null
  })

  // Download report
  downloadReportBtn.addEventListener("click", () => {
    if (!scanResults) {
      return
    }

    const format = selectedFormat || "html"
    downloadReport(format)
  })

  // Start scan function
  function startScan(target, ports, threads, timeout, format) {
    scanInProgress = true
    scanAborted = false
    currentScanId = generateScanId()

    // Show progress overlay
    progressOverlay.classList.remove("hidden")
    progressBar.style.width = "0%"
    progressStatus.textContent = "Initializing scan..."

    // Reset stages
    resetStages()
    stageInit.classList.add("active")

    // Enable both abort buttons
    //stopScanBtn.disabled = false
    progressAbortBtn.disabled = false

    // Enable stop button
    //stopScanBtn.disabled = false

    // Create URL with parameters
    const url = `/api/scan?target=${encodeURIComponent(target)}&ports=${encodeURIComponent(ports)}&threads=${encodeURIComponent(threads)}&timeout=${encodeURIComponent(timeout)}&format=${encodeURIComponent(format)}&scan_id=${currentScanId}`

    try {
      // Use EventSource for real-time updates
      if (typeof EventSource !== "undefined") {
        scanEventSource = new EventSource(url)

        scanEventSource.onopen = () => {
          addTerminalLine("Scan started...", "terminal-info")
        }

        scanEventSource.onerror = (e) => {
          console.error("EventSource error:", e)
          handleScanError("Connection error. Make sure the server is running and try again.")
        }

        scanEventSource.addEventListener("scan_init", (e) => {
          const data = JSON.parse(e.data)
          progressStatus.textContent = data.message
          progressBar.style.width = "10%"
        })

        scanEventSource.addEventListener("port_scan_start", (e) => {
          stageInit.classList.remove("active")
          stageInit.classList.add("completed")
          stagePortScan.classList.add("active")

          const data = JSON.parse(e.data)
          progressStatus.textContent = data.message
          progressBar.style.width = "20%"
        })

        scanEventSource.addEventListener("port_scan_progress", (e) => {
          const data = JSON.parse(e.data)
          progressStatus.textContent = data.message
          progressBar.style.width = `${20 + data.progress * 0.3}%`
        })

        scanEventSource.addEventListener("port_scan_complete", (e) => {
          const data = JSON.parse(e.data)
          progressStatus.textContent = data.message
          progressBar.style.width = "50%"

          if (data.open_ports && data.open_ports.length > 0) {
            addTerminalLine(
              `Found ${data.open_ports.length} open ports: ${data.open_ports.join(", ")}`,
              "terminal-success",
            )
          } else {
            addTerminalLine("No open ports found", "terminal-warning")
          }
        })

        scanEventSource.addEventListener("service_scan_start", (e) => {
          stagePortScan.classList.remove("active")
          stagePortScan.classList.add("completed")
          stageServiceScan.classList.add("active")

          const data = JSON.parse(e.data)
          progressStatus.textContent = data.message
          progressBar.style.width = "55%"
        })

        scanEventSource.addEventListener("service_scan_progress", (e) => {
          const data = JSON.parse(e.data)
          progressStatus.textContent = data.message
          progressBar.style.width = `${55 + data.progress * 0.15}%`
        })

        scanEventSource.addEventListener("service_scan_complete", (e) => {
          const data = JSON.parse(e.data)
          progressStatus.textContent = data.message
          progressBar.style.width = "70%"
        })

        scanEventSource.addEventListener("vuln_scan_start", (e) => {
          stageServiceScan.classList.remove("active")
          stageServiceScan.classList.add("completed")
          stageVulnScan.classList.add("active")

          const data = JSON.parse(e.data)
          progressStatus.textContent = data.message
          progressBar.style.width = "75%"
        })

        scanEventSource.addEventListener("vuln_scan_progress", (e) => {
          const data = JSON.parse(e.data)
          progressStatus.textContent = data.message
          progressBar.style.width = `${75 + data.progress * 0.15}%`
        })

        scanEventSource.addEventListener("vuln_scan_complete", (e) => {
          const data = JSON.parse(e.data)
          progressStatus.textContent = data.message
          progressBar.style.width = "90%"
        })

        scanEventSource.addEventListener("report_generation", (e) => {
          stageVulnScan.classList.remove("active")
          stageVulnScan.classList.add("completed")
          stageReport.classList.add("active")

          const data = JSON.parse(e.data)
          progressStatus.textContent = data.message
          progressBar.style.width = "95%"
        })

        scanEventSource.addEventListener("scan_complete", (e) => {
          stageReport.classList.remove("active")
          stageReport.classList.add("completed")

          const data = JSON.parse(e.data)
          scanResults = data.results

          progressStatus.textContent = "Scan completed successfully"
          progressBar.style.width = "100%"

          // Display results
          displayResults(scanResults)

          // Close connection and reset state
          finishScan()

          // Hide progress overlay after a short delay
          setTimeout(() => {
            progressOverlay.classList.add("hidden")
          }, 1500)

          addTerminalLine("Scan completed successfully", "terminal-success")
        })

        scanEventSource.addEventListener("scan_error", (e) => {
          const data = JSON.parse(e.data)
          handleScanError(data.message)
        })
      } else {
        handleScanError("Your browser does not support server-sent events. Please use a modern browser.")
      }
    } catch (error) {
      console.error("Error setting up EventSource:", error)
      handleScanError("Failed to connect to the server. Please check if the server is running.")
    }
  }

  // Abort scan function
  function abortScan() {
    if (!scanInProgress || !currentScanId) {
      addTerminalLine("No scan in progress to abort", "terminal-warning")
      return
    }

    scanAborted = true
    addTerminalLine("Aborting scan...", "terminal-warning")

    // Disable abort button while processing
    progressAbortBtn.disabled = true
    progressAbortBtn.textContent = "Aborting..."

    // Send abort request
    fetch(`/api/abort?scan_id=${currentScanId}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
    })
      .then((response) => {
        if (!response.ok) {
          throw new Error(`Server returned ${response.status}: ${response.statusText}`)
        }
        return response.json()
      })
      .then((data) => {
        addTerminalLine("Scan aborted successfully", "terminal-warning")
        finishScan()
        progressOverlay.classList.add("hidden")

        // Reset the abort button
        progressAbortBtn.textContent = "Abort Scan"
      })
      .catch((error) => {
        console.error("Error aborting scan:", error)
        addTerminalLine(`Error aborting scan: ${error.message}`, "terminal-error")
        finishScan()
        progressOverlay.classList.add("hidden")

        // Reset the abort button
        progressAbortBtn.textContent = "Abort Scan"
      })
  }

  // Handle scan error
  function handleScanError(message) {
    addTerminalLine(`Error: ${message}`, "terminal-error")
    progressStatus.textContent = `Error: ${message}`
    progressBar.style.width = "100%"
    progressBar.style.backgroundColor = "var(--danger-color)"

    finishScan()

    // Hide progress overlay after a short delay
    setTimeout(() => {
      progressOverlay.classList.add("hidden")
    }, 3000)
  }

  // Finish scan and clean up
  function finishScan() {
    if (scanEventSource) {
      scanEventSource.close()
      scanEventSource = null
    }

    scanInProgress = false
    progressAbortBtn.disabled = true
  }

  // Reset stages
  function resetStages() {
    const stages = [stageInit, stagePortScan, stageServiceScan, stageVulnScan, stageReport]
    stages.forEach((stage) => {
      stage.classList.remove("active", "completed")
    })
  }

  // Display results
  function displayResults(results) {
    if (!results) {
      return
    }

    // Update info section
    infoTarget.textContent = results.scan_info.target
    infoStartTime.textContent = results.scan_info.start_time
    infoDuration.textContent = `${results.scan_info.duration.toFixed(2)} seconds`
    infoOpenPorts.textContent = results.open_ports.length

    // Clear previous results
    portsTable.innerHTML = ""
    vulnsContainer.innerHTML = ""
    rawOutput.textContent = JSON.stringify(results, null, 2)

    // Populate ports table
    if (results.open_ports.length > 0) {
      results.open_ports.forEach((port) => {
        const portStr = port.toString()
        const service = results.services[portStr] || { name: "Unknown", product: "", version: "", extrainfo: "" }

        const row = document.createElement("tr")
        row.innerHTML = `
                    <td>${port}</td>
                    <td>${service.name}</td>
                    <td>${service.product}</td>
                    <td>${service.version}</td>
                    <td>${service.extrainfo}</td>
                `
        portsTable.appendChild(row)
      })
    } else {
      const row = document.createElement("tr")
      row.innerHTML = '<td colspan="5" style="text-align: center;">No open ports found</td>'
      portsTable.appendChild(row)
    }

    // Populate vulnerabilities
    let vulnFound = false

    results.open_ports.forEach((port) => {
      const portStr = port.toString()
      if (results.vulnerabilities[portStr] && results.vulnerabilities[portStr].length > 0) {
        vulnFound = true
        const service = results.services[portStr] || { name: "Unknown", product: "", version: "" }

        const portSection = document.createElement("div")
        portSection.className = "vuln-port-section"

        const portHeader = document.createElement("div")
        portHeader.className = "vuln-port-header"
        portHeader.textContent = `Port ${port} - ${service.name} - ${service.product} ${service.version}`

        const vulnTable = document.createElement("table")
        vulnTable.className = "vuln-table"
        vulnTable.innerHTML = `
                    <thead>
                        <tr>
                            <th>CVE ID</th>
                            <th>CVSS Score</th>
                            <th>Severity</th>
                            <th>Description</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                `

        const vulnTableBody = vulnTable.querySelector("tbody")

        results.vulnerabilities[portStr].forEach((vuln) => {
          let severityClass = "severity-low"
          if (vuln.severity === "HIGH") {
            severityClass = "severity-high"
          } else if (vuln.severity === "MEDIUM") {
            severityClass = "severity-medium"
          }

          const vulnRow = document.createElement("tr")
          vulnRow.innerHTML = `
                        <td class="cve-id">${vuln.cve_id}</td>
                        <td class="${severityClass}">${vuln.cvss_score}</td>
                        <td class="${severityClass}">${vuln.severity}</td>
                        <td>${vuln.description}</td>
                    `
          vulnTableBody.appendChild(vulnRow)
        })

        portSection.appendChild(portHeader)
        portSection.appendChild(vulnTable)
        vulnsContainer.appendChild(portSection)
      }
    })

    if (!vulnFound) {
      const noVulnMsg = document.createElement("p")
      noVulnMsg.textContent = "No vulnerabilities found for any service."
      noVulnMsg.style.textAlign = "center"
      noVulnMsg.style.padding = "20px"
      vulnsContainer.appendChild(noVulnMsg)
    }

    // Show results container
    resultsContainer.classList.remove("hidden")
  }

  // Download report
  function downloadReport(format) {
    if (!scanResults || !currentScanId) {
      addTerminalLine("Error: No scan results available to download", "terminal-error")
      return
    }

    const url = `/api/report?scan_id=${currentScanId}&format=${format}`

    addTerminalLine(`Downloading report in ${format} format...`, "terminal-info")

    // Create a temporary link and click it to download
    const a = document.createElement("a")
    a.href = url
    a.download = `vulnerability_scan_${scanResults.scan_info.target}_${new Date().toISOString().slice(0, 10)}.${format}`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)

    // Add a small delay to check if download started
    setTimeout(() => {
      fetch(url, { method: "HEAD" })
        .then((response) => {
          if (!response.ok) {
            addTerminalLine("Error downloading report. Please try again.", "terminal-error")
          }
        })
        .catch(() => {
          // This is expected as the browser will navigate away to download
        })
    }, 1000)
  }

  // Generate a random scan ID
  function generateScanId() {
    return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15)
  }

  // Terminal command handling
  document.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && document.activeElement === document.body) {
      const lastPrompt = Array.from(terminalOutput.querySelectorAll(".terminal-prompt")).pop()
      if (lastPrompt && lastPrompt.nextElementSibling === null) {
        const command = prompt("Enter command:")
        if (command) {
          handleTerminalCommand(command)
        }
      }
    }
  })

  function handleTerminalCommand(command) {
    addTerminalLine(command, "terminal-command")

    const parts = command.trim().split(" ")
    const cmd = parts[0].toLowerCase()

    switch (cmd) {
      case "help":
        addTerminalLine("Available commands:", "terminal-output")
        addTerminalLine("  help - Show this help message", "terminal-output")
        addTerminalLine("  clear - Clear terminal output", "terminal-output")
        addTerminalLine("  scan <target> [options] - Start a vulnerability scan", "terminal-output")
        addTerminalLine("  abort - Abort current scan", "terminal-output")
        addTerminalLine("  status - Check server status", "terminal-output")
        break

      case "clear":
        terminalOutput.innerHTML = ""
        addTerminalLine("Terminal cleared", "terminal-output")
        addTerminalLine("$", "terminal-prompt")
        break

      case "status":
        addTerminalLine("Checking server status...", "terminal-output")
        checkServerHealth()
        break

      case "scan":
        if (parts.length < 2) {
          addTerminalLine("Error: Target is required", "terminal-error")
          break
        }

        const target = parts[1]
        let ports = "1-1000"
        let threads = "10"
        let timeout = "1.0"
        let format = "html"

        // Parse options
        for (let i = 2; i < parts.length; i++) {
          if (parts[i] === "-p" && i + 1 < parts.length) {
            ports = parts[i + 1]
            i++
          } else if (parts[i] === "-t" && i + 1 < parts.length) {
            threads = parts[i + 1]
            i++
          } else if (parts[i] === "-T" && i + 1 < parts.length) {
            timeout = parts[i + 1]
            i++
          } else if (parts[i] === "-f" && i + 1 < parts.length) {
            format = parts[i + 1]
            i++
          }
        }

        // Update form values
        document.getElementById("target").value = target
        document.getElementById("ports").value = ports
        document.getElementById("threads").value = threads
        document.getElementById("timeout").value = timeout
        document.getElementById("format").value = format

        // Store the selected format
        selectedFormat = format

        // Start scan
        startScan(target, ports, threads, timeout, format)
        break

      case "abort":
        if (!scanInProgress) {
          addTerminalLine("No scan in progress", "terminal-warning")
          break
        }

        abortScan()
        break

      default:
        addTerminalLine(`Command not found: ${cmd}`, "terminal-error")
        break
    }
  }
})

