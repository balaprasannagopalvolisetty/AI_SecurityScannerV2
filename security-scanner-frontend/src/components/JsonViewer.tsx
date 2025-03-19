import type React from "react"

interface JsonViewerProps {
  data: any
}

const JsonViewer: React.FC<JsonViewerProps> = ({ data }) => {
  const formatJson = (json: any): string => {
    return JSON.stringify(json, null, 2)
  }

  const syntaxHighlight = (json: string): string => {
    return json
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(
        /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g,
        (match) => {
          let cls = "json-number"
          if (/^"/.test(match)) {
            if (/:$/.test(match)) {
              cls = "json-key"
            } else {
              cls = "json-string"
            }
          } else if (/true|false/.test(match)) {
            cls = "json-boolean"
          } else if (/null/.test(match)) {
            cls = "json-null"
          }
          return `<span class="${cls}">${match}</span>`
        },
      )
  }

  return <div className="json-viewer" dangerouslySetInnerHTML={{ __html: syntaxHighlight(formatJson(data)) }} />
}

export default JsonViewer

