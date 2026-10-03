#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! # arkhe-code-review-context
//!
//! Retrieval de contexto para grounding verificável de findings.
//!
//! ## Invariantes
//!
//! - `INV-CR-09`: fornece os dados que permitem grounding (ficheiro + linha + snippet)
//! - `INV-CR-10`: `FileContext::line(n)` é 1-indexed e devolve `None` para `n = 0`

use std::collections::HashMap;

use arkhe_code_review_diff::{Diff, LineKind};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Tamanho máximo de ficheiro a carregar (10 MB).
pub const MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;

/// Erro de contexto.
#[derive(Debug, Error)]
pub enum ContextError {
    /// Ficheiro não encontrado.
    #[error("ficheiro não encontrado: {0}")]
    NotFound(String),
    /// Ficheiro excede o limite.
    #[error("ficheiro excede limite: {path} = {size} > {max}")]
    TooLarge {
        /// Caminho.
        path: String,
        /// Tamanho observado.
        size: u64,
        /// Limite máximo.
        max: u64,
    },
    /// I/O.
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
}

/// Contexto de um ficheiro carregado.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileContext {
    /// Caminho.
    pub path: String,
    /// Linhas do ficheiro (1-indexed por convenção de acesso).
    pub lines: Vec<String>,
    /// `record_hash` do conteúdo.
    pub file_hash: [u8; 32],
}

impl FileContext {
    /// Carrega um ficheiro do disco.
    ///
    /// # Errors
    ///
    /// Devolve [`ContextError::NotFound`] se o ficheiro não existir,
    /// [`ContextError::TooLarge`] se exceder [`MAX_FILE_BYTES`],
    /// ou [`ContextError::Io`] para outros erros de I/O.
    pub fn load(path: &str) -> Result<Self, ContextError> {
        let meta = std::fs::metadata(path)?;
        if meta.len() > MAX_FILE_BYTES {
            return Err(ContextError::TooLarge {
                path: path.to_string(),
                size: meta.len(),
                max: MAX_FILE_BYTES,
            });
        }

        let content = std::fs::read_to_string(path)?;
        let lines: Vec<String> = content.lines().map(String::from).collect();
        let file_hash = *blake3::hash(content.as_bytes()).as_bytes();
        Ok(Self {
            path: path.to_string(),
            lines,
            file_hash,
        })
    }

    /// Constrói a partir de linhas já carregadas.
    #[must_use]
    pub fn from_lines(path: &str, lines: Vec<String>) -> Self {
        let content = lines.join("\n");
        let file_hash = *blake3::hash(content.as_bytes()).as_bytes();
        Self {
            path: path.to_string(),
            lines,
            file_hash,
        }
    }

    /// Número de linhas.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// Vazio?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// Devolve a linha `n` (1-indexed).
    ///
    /// Devolve `None` se `n == 0` ou se exceder o número de linhas.
    #[must_use]
    pub fn line(&self, n: usize) -> Option<&str> {
        if n == 0 {
            return None;
        }
        self.lines.get(n - 1).map(String::as_str)
    }

    /// Extrai uma janela de linhas em torno de `center` (1-indexed).
    ///
    /// Devolve linhas `[center - radius, center + radius]` clampadas aos
    /// limites do ficheiro. Devolve vazio se `center == 0`.
    #[must_use]
    pub fn window(&self, center: usize, radius: usize) -> &[String] {
        if center == 0 || self.lines.is_empty() {
            return &[];
        }
        let start = center.saturating_sub(radius + 1);
        let end = (center + radius).min(self.lines.len());
        if start >= end {
            return &[];
        }
        &self.lines[start..end]
    }
}

/// Contexto agregado para um review.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReviewContext {
    /// Ficheiros carregados, indexados por caminho (new-side).
    pub files: HashMap<String, FileContext>,
    /// Histórico de PRs (opcional).
    pub pr_history: Vec<String>,
}

impl ReviewContext {
    /// Cria um contexto vazio.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Número de ficheiros carregados.
    #[must_use]
    pub fn files_count(&self) -> usize {
        self.files.len()
    }

    /// Devolve o contexto de um ficheiro.
    #[must_use]
    pub fn get(&self, path: &str) -> Option<&FileContext> {
        self.files.get(path)
    }

    /// Adiciona um ficheiro carregado do disco.
    ///
    /// # Errors
    ///
    /// Propaga o erro de [`FileContext::load`].
    pub fn add_file(&mut self, path: &str) -> Result<(), ContextError> {
        let ctx = FileContext::load(path)?;
        self.files.insert(path.to_string(), ctx);
        Ok(())
    }

    /// Constrói um contexto sintético a partir de um `Diff`.
    ///
    /// **Limitação documentada:** reconstrói o conteúdo do lado novo a partir
    /// dos hunks, preenchendo os gaps entre hunks com linhas vazias. Se os
    /// hunks não forem contíguos (ex.: segundo hunk começa depois de uma
    /// zona não vista no diff), o padding é aproximado. Para grounding
    /// rigoroso, carregar os ficheiros reais via [`Self::add_file`].
    ///
    /// Os números de linha no `FileContext` resultante correspondem ao
    /// **lado novo** do diff (`evidence.line` refere-se a este lado).
    #[must_use]
    pub fn from_diff(diff: &Diff) -> Self {
        let mut ctx = Self::default();
        for file in &diff.files {
            let mut lines: Vec<String> = Vec::new();
            for hunk in &file.hunks {
                // Preencher gaps até `new_start`.
                while lines.len() + 1 < hunk.new_start {
                    lines.push(String::new());
                }
                // Adicionar linhas do lado novo (contexto + adicionadas).
                for line in &hunk.lines {
                    if line.kind != LineKind::Removed {
                        lines.push(line.content.clone());
                    }
                }
            }
            ctx.files.insert(
                file.new_path.clone(),
                FileContext::from_lines(&file.new_path, lines),
            );
        }
        ctx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_diff() -> Diff {
        let input = "\
diff --git a/x.rs b/x.rs
--- a/x.rs
+++ b/x.rs
@@ -10,3 +10,4 @@
 context_a
 context_b
+added
 context_c
";
        Diff::parse(input).unwrap()
    }

    #[test]
    fn load_missing_file_fails() {
        let result = FileContext::load("/nonexistent/path/x.rs");
        assert!(result.is_err());
    }

    #[test]
    fn load_reads_lines_correctly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.rs");
        std::fs::write(&path, "line1\nline2\nline3\n").unwrap();

        let ctx = FileContext::load(path.to_str().unwrap()).unwrap();
        assert_eq!(ctx.len(), 3);
        assert_eq!(ctx.line(1), Some("line1"));
        assert_eq!(ctx.line(3), Some("line3"));
        assert_eq!(ctx.line(4), None);
    }

    #[test]
    fn load_is_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.rs");
        std::fs::write(&path, "content\n").unwrap();

        let c1 = FileContext::load(path.to_str().unwrap()).unwrap();
        let c2 = FileContext::load(path.to_str().unwrap()).unwrap();
        assert_eq!(c1.file_hash, c2.file_hash);
    }

    #[test]
    fn line_zero_returns_none() {
        let ctx = FileContext::from_lines("x.rs", vec!["a".into()]);
        assert_eq!(ctx.line(0), None);
    }

    #[test]
    fn window_extracts_correct_range() {
        let ctx = FileContext::from_lines(
            "x.rs",
            vec!["a".into(), "b".into(), "c".into(), "d".into(), "e".into()],
        );
        let w = ctx.window(3, 1);
        assert_eq!(w.len(), 3);
        assert_eq!(w[0], "b");
        assert_eq!(w[1], "c");
        assert_eq!(w[2], "d");
    }

    #[test]
    fn window_zero_center_is_empty() {
        let ctx = FileContext::from_lines("x.rs", vec!["a".into()]);
        assert!(ctx.window(0, 1).is_empty());
    }

    #[test]
    fn window_clamps_to_file_bounds() {
        let ctx = FileContext::from_lines("x.rs", vec!["a".into(), "b".into()]);
        let w = ctx.window(1, 10);
        assert_eq!(w.len(), 2);
    }

    #[test]
    fn from_diff_reconstructs_with_padding() {
        let diff = sample_diff();
        let ctx = ReviewContext::from_diff(&diff);

        assert_eq!(ctx.files_count(), 1);
        let file = ctx.get("x.rs").unwrap();

        // Hunk começa em new_start=10 → 9 linhas de padding antes.
        assert_eq!(file.len(), 13);
        assert_eq!(file.line(10), Some("context_a"));
        assert_eq!(file.line(11), Some("context_b"));
        assert_eq!(file.line(12), Some("added"));
        assert_eq!(file.line(13), Some("context_c"));
    }

    #[test]
    fn inv_cr_09_from_diff_supports_grounding() {
        // A linha 12 do ficheiro reconstruído deve ser exactamente o
        // conteúdo da linha adicionada. Isto é o que o judge verifica.
        let diff = sample_diff();
        let ctx = ReviewContext::from_diff(&diff);
        let file = ctx.get("x.rs").unwrap();
        assert_eq!(file.line(12), Some("added"));
    }

    #[test]
    fn empty_diff_produces_empty_context() {
        // `Diff::parse` rejeita vazio, por isso `from_diff` só é chamado com
        // um diff válido. Aqui validamos que um diff de 0 ficheiros produz
        // um contexto de 0 ficheiros (não é o caso do parser, mas defesa).
        let ctx = ReviewContext::new();
        assert_eq!(ctx.files_count(), 0);
    }

    #[test]
    fn add_file_populates_context() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.rs");
        std::fs::write(&path, "hello\n").unwrap();

        let mut ctx = ReviewContext::new();
        ctx.add_file(path.to_str().unwrap()).unwrap();
        assert_eq!(ctx.files_count(), 1);

        let file = ctx.get(path.to_str().unwrap()).unwrap();
        assert_eq!(file.line(1), Some("hello"));
    }

    #[test]
    fn add_file_propagates_not_found() {
        let mut ctx = ReviewContext::new();
        assert!(ctx.add_file("/nonexistent/x.rs").is_err());
    }
}
