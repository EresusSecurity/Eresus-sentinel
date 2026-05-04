"""FP audit: scan benign code corpora and assert 0 injection findings.

Rules with require_file_context=True will not fire on files without LLM
imports — the entire test corpus below is deliberately LLM-free code,
so injection rules must produce 0 findings.

API key rules are NOT tested here (they have their own signature tests);
this file focuses on injection/command/eval rules which are the high-FP risk.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from sentinel.sast.multilang_scanner import MultiLangSASTScanner

_INJECTION_RULE_IDS = {
    "MLSAST-001", "MLSAST-001-TS",
    "MLSAST-002", "MLSAST-003", "MLSAST-004",
    "MLSAST-005",
    "MLSAST-020", "MLSAST-020-TS",
    "MLSAST-021", "MLSAST-022", "MLSAST-023",
    "MLSAST-040",
    "MLSAST-060",
    "MLSAST-080", "MLSAST-082", "MLSAST-083",
    "MLSAST-100", "MLSAST-101", "MLSAST-102",
    "MLSAST-110", "MLSAST-120", "MLSAST-121",
    "MLSAST-130", "MLSAST-132",
}


def _scan_content(content: str, suffix: str) -> list:
    scanner = MultiLangSASTScanner(min_confidence=0.0)
    with tempfile.NamedTemporaryFile(suffix=suffix, mode="w", delete=False) as f:
        f.write(content)
        fpath = f.name
    try:
        result = scanner.scan_path(fpath)
        return [fi for fi in result.findings if fi.rule_id in _INJECTION_RULE_IDS]
    finally:
        Path(fpath).unlink(missing_ok=True)


# ── JavaScript / TypeScript — no LLM context ──────────────────────

def test_fp_js_express_server():
    """Plain Express route handler — no LLM imports."""
    code = """
const express = require('express');
const app = express();
app.use(express.json());

app.post('/users', async (req, res) => {
    const { username, email } = req.body;
    const user = await db.users.create({ username, email });
    res.json({ id: user.id, messages: ['User created'] });
});

app.get('/content/:id', (req, res) => {
    const content = req.params.id;
    res.json({ content, prompt: 'Hello', system: 'response' });
});
"""
    findings = _scan_content(code, ".js")
    assert findings == [], f"Expected 0 injection findings on plain Express, got {findings}"


def test_fp_js_react_component():
    """React component with messages prop — no LLM."""
    code = """
import React, { useState } from 'react';

function ChatUI({ messages, onSend }) {
    const [input, setInput] = useState('');

    const handleSend = () => {
        const content = input.trim();
        onSend({ role: 'user', content });
    };

    return (
        <div>
            {messages.map(m => <div key={m.id}>{m.content}</div>)}
            <input value={input} onChange={e => setInput(e.target.value)} />
            <button onClick={handleSend}>Send</button>
        </div>
    );
}

export default ChatUI;
"""
    findings = _scan_content(code, ".tsx")
    assert findings == [], f"Expected 0 findings on React component, got {findings}"


def test_fp_js_env_vars_non_llm():
    """process.env usage without LLM-related var names."""
    code = """
const port = process.env.PORT || 3000;
const dbUrl = process.env.DATABASE_URL;
const nodeEnv = process.env.NODE_ENV;

function getConfig() {
    return {
        port,
        dbUrl,
        env: nodeEnv,
    };
}
"""
    findings = _scan_content(code, ".js")
    assert findings == [], f"Expected 0 findings on non-LLM env vars, got {findings}"


def test_fp_js_writeFile_generic():
    """fs.writeFile used normally without LLM output."""
    code = """
const fs = require('fs');

async function saveReport(data) {
    const reportPath = './report.json';
    await fs.promises.writeFile(reportPath, JSON.stringify(data, null, 2));
    console.log('Report saved');
}
"""
    findings = _scan_content(code, ".js")
    assert findings == [], f"Expected 0 findings on generic writeFile, got {findings}"


# ── Java — no LLM context ─────────────────────────────────────────

def test_fp_java_spring_controller():
    """Spring MVC controller with @RequestParam — no LLM dependency."""
    code = """
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class UserController {

    @GetMapping("/search")
    public List<User> searchUsers(@RequestParam String query,
                                   @RequestParam(required = false) String filter) {
        return userService.findByQuery(query, filter);
    }

    @PostMapping("/users")
    public User createUser(@RequestBody CreateUserRequest request) {
        return userService.create(request.getName(), request.getEmail());
    }
}
"""
    findings = _scan_content(code, ".java")
    assert findings == [], f"Expected 0 findings on plain Spring controller, got {findings}"


def test_fp_java_runtime_exec_non_llm():
    """Runtime.exec() with a static command — no LLM variable."""
    code = """
public class ScriptRunner {
    public void runScript(String scriptPath) throws Exception {
        String[] command = {"/bin/sh", scriptPath};
        Process proc = Runtime.getRuntime().exec(command);
        proc.waitFor();
    }
}
"""
    findings = _scan_content(code, ".java")
    assert findings == [], f"Expected 0 findings on static Runtime.exec, got {findings}"


def test_fp_java_object_input_stream():
    """ObjectInputStream with filter — FP suppress."""
    code = """
import java.io.*;

public class SafeDeserializer {
    public Object deserialize(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        ois.setObjectInputFilter(ObjectInputFilter.Config.createFilter("java.lang.*;!*"));
        return ois.readObject();
    }
}
"""
    findings = _scan_content(code, ".java")
    assert findings == [], f"Expected 0 findings on ObjectInputStream with filter, got {findings}"


# ── Go — no LLM context ───────────────────────────────────────────

def test_fp_go_http_handler():
    """Standard Go HTTP handler with FormValue — no LLM."""
    code = """
package main

import (
    "encoding/json"
    "net/http"
    "os"
)

func searchHandler(w http.ResponseWriter, r *http.Request) {
    query := r.FormValue("q")
    filter := r.URL.Query().Get("filter")
    content := query + filter
    json.NewEncoder(w).Encode(map[string]string{"result": content})
}

func configHandler(w http.ResponseWriter, r *http.Request) {
    apiURL := os.Getenv("API_BASE_URL")
    _ = apiURL
}
"""
    findings = _scan_content(code, ".go")
    assert findings == [], f"Expected 0 findings on plain Go handler, got {findings}"


def test_fp_go_exec_static_command():
    """exec.Command with a static argument — no LLM variable."""
    code = """
package main

import (
    "os/exec"
)

func runGit(repoPath string) error {
    cmd := exec.Command("git", "-C", repoPath, "pull")
    return cmd.Run()
}
"""
    findings = _scan_content(code, ".go")
    assert findings == [], f"Expected 0 findings on static exec.Command, got {findings}"


def test_fp_go_os_getenv_non_sensitive():
    """os.Getenv with generic env var — no LLM context."""
    code = """
package main

import "os"

func main() {
    port := os.Getenv("PORT")
    dbHost := os.Getenv("DB_HOST")
    _ = port
    _ = dbHost
}
"""
    findings = _scan_content(code, ".go")
    assert findings == [], f"Expected 0 findings on non-sensitive os.Getenv, got {findings}"


# ── Ruby — no LLM context ─────────────────────────────────────────

def test_fp_ruby_rails_controller():
    """Rails controller with params — no LLM dependency."""
    code = """
class UsersController < ApplicationController
  def create
    @user = User.new(user_params)
    message = params[:message]
    if @user.save
      render json: { user: @user, messages: ['Created'] }
    end
  end

  private

  def user_params
    params.require(:user).permit(:name, :email)
  end
end
"""
    findings = _scan_content(code, ".rb")
    assert findings == [], f"Expected 0 findings on plain Rails controller, got {findings}"


def test_fp_ruby_yaml_load_with_permitted():
    """YAML.safe_load — permitted, not YAML.load."""
    code = """
require 'yaml'

def load_config(path)
  content = File.read(path)
  YAML.safe_load(content, permitted_classes: [Symbol])
end
"""
    findings = _scan_content(code, ".rb")
    assert findings == [], f"Expected 0 findings on YAML.safe_load, got {findings}"


# ── PHP — no LLM context ──────────────────────────────────────────

def test_fp_php_curl_no_llm():
    """PHP curl to a non-LLM API endpoint."""
    code = """<?php
function fetchWeather(string $city): array {
    $ch = curl_init();
    $url = "https://api.weather.example.com/current?city=" . urlencode($city);
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    curl_close($ch);
    return json_decode($response, true);
}
"""
    findings = _scan_content(code, ".php")
    assert findings == [], f"Expected 0 findings on plain PHP curl, got {findings}"


# ── C# — no LLM context ───────────────────────────────────────────

def test_fp_csharp_aspnet_controller():
    """ASP.NET Core controller with [FromBody] — no Semantic Kernel."""
    code = """
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class ProductsController : ControllerBase
{
    [HttpPost]
    public async Task<IActionResult> CreateProduct([FromBody] CreateProductRequest request)
    {
        var product = await _productService.CreateAsync(request.Name, request.Price);
        return Ok(new { product.Id, Messages = new[] { "Product created" } });
    }
}
"""
    findings = _scan_content(code, ".cs")
    assert findings == [], f"Expected 0 findings on plain ASP.NET controller, got {findings}"


def test_fp_csharp_process_start_static():
    """Process.Start with a static command — no LLM variable."""
    code = """
using System.Diagnostics;

public class ProcessHelper
{
    public static void OpenUrl(string url)
    {
        var info = new ProcessStartInfo
        {
            FileName = "xdg-open",
            Arguments = url,
            UseShellExecute = false,
        };
        Process.Start(info);
    }
}
"""
    findings = _scan_content(code, ".cs")
    assert findings == [], f"Expected 0 findings on static Process.Start, got {findings}"
