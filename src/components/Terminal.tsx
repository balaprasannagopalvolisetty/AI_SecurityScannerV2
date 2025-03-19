"use client"

import type React from "react"
import { useState, useEffect, useRef } from "react"
import { useNavigate } from "react-router-dom"
import MatrixEffect from "./MatrixEffect"

interface TerminalOutput {
  text: string
  type: "command" | "output" | "error" | "success" | "info" | "warning"
}

const Terminal: React.FC = () => {
  const [input, setInput] = useState("")
  const [outputs, setOutputs] = useState<TerminalOutput[]>([
    { text: "Advanced Web Security Scanner v1.0.0", type: "info" },
    { text: 'Type "help" to see available commands', type: "info" },
  ])
  const [history, setHistory] = useState<string[]>([])
  const [historyIndex, setHistoryIndex] = useState(-1)
  const inputRef = useRef<HTMLInputElement>(null)
  const outputsEndRef = useRef<HTMLDivElement>(null)
  const navigate = useNavigate()

  useEffect(() => {
    // Scroll to bottom when outputs change
    outputsEndRef.current?.scrollIntoView({ behavior: "smooth" })
  }, [outputs])

  useEffect(() => {
    // Focus input on mount
    inputRef.current?.focus()
  }, [])

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setInput(e.target.value)
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      handleCommand()
    } else if (e.key === "ArrowUp") {
      e.preventDefault()
      navigateHistory(-1)
    } else if (e.key === "ArrowDown") {
      e.preventDefault()
      navigateHistory(1)
    }
  }

  const navigateHistory = (direction: number) => {
    const newIndex = historyIndex + direction
    if (newIndex >= -1 && newIndex < history.length) {
      setHistoryIndex(newIndex)
      if (newIndex === -1) {
        setInput("")
      } else {
        setInput(history[newIndex])
      }
    }
  }

  const handleCommand = () => {
    if (!input.trim()) return

    // Add command to output
    const newOutputs = [...outputs, { text: `$ ${input}`, type: "command" }]

    // Add command to history
    const newHistory = [input, ...history].slice(0, 50)
    setHistory(newHistory)
    setHistoryIndex(-1)

    // Process command
    const command = input.trim().toLowerCase()
    const args = command.split(" ")

    switch (args[0]) {
      case "help":
        newOutputs.push({
          text: `
Available commands:
  help                 - Show this help message
  clear                - Clear the terminal
  scan <url>           - Start a new scan
  status <scan_id>     - Check scan status
  report <scan_id>     - Get scan report
  dashboard            - Go to dashboard
  exit                 - Exit terminal
          `,
          type: "info",
        })
        break

      case "clear":
        setOutputs([])
        setInput("")
        return

      case "scan":
        if (args.length < 2) {
          newOutputs.push({ text: "Error: Missing URL parameter", type: "error" })
        } else {
          const url = args[1]
          newOutputs.push({ text: `Starting scan for ${url}...`, type: "info" })

          // Simulate API call
          setTimeout(() => {
            const scanId = `scan_${Math.floor(Math.random() * 1000)}`
            setOutputs((prev) => [
              ...prev,
              {
                text: `Scan started with ID: ${scanId}
Use 'status ${scanId}' to check the scan status`,
                type: "success",
              },
            ])
          }, 1500)
        }
        break

      case "status":
        if (args.length < 2) {
          newOutputs.push({ text: "Error: Missing scan ID parameter", type: "error" })
        } else {
          const scanId = args[1]
          newOutputs.push({ text: `Checking status for scan ${scanId}...`, type: "info" })

          // Simulate API call
          setTimeout(() => {
            const statuses = ["pending", "scanning", "completed"]
            const randomStatus = statuses[Math.floor(Math.random() * statuses.length)]
            setOutputs((prev) => [
              ...prev,
              {
                text: `Scan ${scanId} status: ${randomStatus}`,
                type: randomStatus === "completed" ? "success" : "info",
              },
            ])
          }, 1000)
        }
        break

      case "report":
        if (args.length < 2) {
          newOutputs.push({ text: "Error: Missing scan ID parameter", type: "error" })
        } else {
          const scanId = args[1]
          navigate(`/results/${scanId}`)
        }
        break

      case "dashboard":
        navigate("/dashboard")
        break

      case "exit":
        newOutputs.push({ text: "Exiting terminal...", type: "info" })
        setTimeout(() => {
          navigate("/dashboard")
        }, 1000)
        break

      default:
        newOutputs.push({ text: `Command not found: ${args[0]}`, type: "error" })
    }

    setOutputs(newOutputs)
    setInput("")
  }

  return (
    <div className="terminal">
      <MatrixEffect />
      <div className="terminal-header">
        <div className="terminal-title">security-scanner@localhost:~</div>
        <div className="terminal-controls">
          <div className="terminal-control close"></div>
          <div className="terminal-control minimize"></div>
          <div className="terminal-control maximize"></div>
        </div>
      </div>
      <div className="terminal-body">
        {outputs.map((output, index) => (
          <div key={index} className={`terminal-output ${output.type}`}>
            {output.text}
          </div>
        ))}
        <div className="terminal-input-line">
          <div className="terminal-prompt">$</div>
          <input
            ref={inputRef}
            type="text"
            className="terminal-input"
            value={input}
            onChange={handleInputChange}
            onKeyDown={handleKeyDown}
            autoFocus
          />
        </div>
        <div ref={outputsEndRef} />
      </div>
    </div>
  )
}

export default Terminal

