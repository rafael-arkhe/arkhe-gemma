#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

//! # arkhe-code-review-diff
//!
//! Parser de unified diff (formato `git diff`) com validação de hunk counts.
//!
//! ## Invariantes
//!
//! - `INV-CR-02`: Diff vazio é rejeitado (fail-closed)
//! - `INV-CR-11`: Hunk counts correspondem às linhas reais

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Erro de parsing de diff.
#[derive(Debug, Error)]
pub enum DiffError {
    /// Diff vazio.
    #[error("diff vazio")]
    Empty,
    /// Linha malformada.
    #[error("linha {line} malformada: {content}")]
    Malformed {
        /// Número da linha.
        line: usize,
        /// Conteúdo.
        content: String,
    },
    /// Hunk header inválido.
    #[error("hunk header inválido na linha {line}: {header}")]
    InvalidHunkHeader {
        /// Linha.
        line: usize,
        /// Header.
        header: String,
    },
    /// Contagem de hunk não corresponde às linhas reais (`INV-CR-11`).
    #[error(
        "hunk em {file}: esperado old={old_expected}/new={new_expected}, \
         obtido old={old_actual}/new={new_actual}"
    )]
    HunkCountMismatch {
        /// Ficheiro.
        file: String,
        /// Esperado (old).
        old_expected: usize,
        /// Obtido (old).
        old_actual: usize,
        /// Esperado (new).
        new_expected: usize,
        /// Obtido (new).
        new_actual: usize,
    },
}

/// Tipo de linha num hunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineKind {
    /// Contexto.
    Context,
    /// Adicionada.
    Added,
    /// Removida.
    Removed,
}

/// Linha do diff.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffLine {
    /// Tipo.
    pub kind: LineKind,
    /// Conteúdo (sem prefixo).
    pub content: String,
    /// Número da linha no ficheiro antigo.
    pub old_line: Option<usize>,
    /// Número da linha no ficheiro novo.
    pub new_line: Option<usize>,
}

/// Hunk individual.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hunk {
    /// Linha de início no ficheiro antigo.
    pub old_start: usize,
    /// Número de linhas no ficheiro antigo.
    pub old_count: usize,
    /// Linha de início no ficheiro novo.
    pub new_start: usize,
    /// Número de linhas no ficheiro novo.
    pub new_count: usize,
    /// Linhas.
    pub lines: Vec<DiffLine>,
}

/// Ficheiro alterado.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileDiff {
    /// Caminho antigo.
    pub old_path: String,
    /// Caminho novo.
    pub new_path: String,
    /// Hunks.
    pub hunks: Vec<Hunk>,
}

/// Diff completo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diff {
    /// Ficheiros alterados.
    pub files: Vec<FileDiff>,
}

impl Diff {
    /// Parse de um unified diff.
    ///
    /// # Errors
    ///
    /// - [`DiffError::Empty`] se o input for vazio (`INV-CR-02`)
    /// - [`DiffError::Malformed`] se uma linha não seguir o formato
    /// - [`DiffError::InvalidHunkHeader`] se o header de hunk for inválido
    /// - [`DiffError::HunkCountMismatch`] se as contagens divergirem (`INV-CR-11`)
    pub fn parse(input: &str) -> Result<Self, DiffError> {
        if input.trim().is_empty() {
            return Err(DiffError::Empty);
        }

        let mut files: Vec<FileDiff> = Vec::new();
        let mut current: Option<FileDiff> = None;
        let mut current_hunk: Option<Hunk> = None;
        let mut old_line: usize = 0;
        let mut new_line: usize = 0;

        for (idx, raw) in input.lines().enumerate() {
            let line_no = idx + 1;

            if let Some(rest) = raw.strip_prefix("diff --git ") {
                flush_hunk(&mut current_hunk, &mut current);
                if let Some(f) = current.take() {
                    files.push(f);
                }
                let parts: Vec<&str> = rest.split_whitespace().collect();
                if parts.len() != 2 {
                    return Err(DiffError::Malformed {
                        line: line_no,
                        content: raw.to_string(),
                    });
                }
                current = Some(FileDiff {
                    old_path: parts[0].trim_start_matches("a/").to_string(),
                    new_path: parts[1].trim_start_matches("b/").to_string(),
                    hunks: Vec::new(),
                });
            } else if raw.starts_with("--- ")
                || raw.starts_with("+++ ")
                || raw.starts_with("index ")
                || raw.starts_with("new file mode")
                || raw.starts_with("deleted file mode")
                || raw.starts_with("old mode")
                || raw.starts_with("new mode")
                || raw.starts_with("similarity index")
                || raw.starts_with("rename from ")
                || raw.starts_with("rename to ")
                || raw.starts_with("Binary files ")
            {
                continue;
            } else if raw.starts_with("@@ ") {
                flush_hunk(&mut current_hunk, &mut current);
                let (os, oc, ns, nc) =
                    parse_hunk_header(raw).ok_or_else(|| DiffError::InvalidHunkHeader {
                        line: line_no,
                        header: raw.to_string(),
                    })?;
                old_line = os;
                new_line = ns;
                current_hunk = Some(Hunk {
                    old_start: os,
                    old_count: oc,
                    new_start: ns,
                    new_count: nc,
                    lines: Vec::new(),
                });
            } else if let Some(h) = current_hunk.as_mut() {
                let (kind, content) = if let Some(c) = raw.strip_prefix('+') {
                    (LineKind::Added, c)
                } else if let Some(c) = raw.strip_prefix('-') {
                    (LineKind::Removed, c)
                } else if let Some(c) = raw.strip_prefix(' ') {
                    (LineKind::Context, c)
                } else if raw.is_empty() {
                    (LineKind::Context, "")
                } else {
                    // Linhas que não pertencem a nenhum hunk activo.
                    continue;
                };

                let (ol, nl) = match kind {
                    LineKind::Context => {
                        let r = (Some(old_line), Some(new_line));
                        old_line += 1;
                        new_line += 1;
                        r
                    }
                    LineKind::Added => {
                        let r = (None, Some(new_line));
                        new_line += 1;
                        r
                    }
                    LineKind::Removed => {
                        let r = (Some(old_line), None);
                        old_line += 1;
                        r
                    }
                };

                h.lines.push(DiffLine {
                    kind,
                    content: content.to_string(),
                    old_line: ol,
                    new_line: nl,
                });
            }
        }

        flush_hunk(&mut current_hunk, &mut current);
        if let Some(f) = current.take() {
            files.push(f);
        }

        if files.is_empty() {
            return Err(DiffError::Empty);
        }

        // Validação de hunk counts (`INV-CR-11`)
        for file in &files {
            for hunk in &file.hunks {
                let old_actual = hunk
                    .lines
                    .iter()
                    .filter(|l| l.kind != LineKind::Added)
                    .count();
                let new_actual = hunk
                    .lines
                    .iter()
                    .filter(|l| l.kind != LineKind::Removed)
                    .count();
                if old_actual != hunk.old_count || new_actual != hunk.new_count {
                    return Err(DiffError::HunkCountMismatch {
                        file: file.new_path.clone(),
                        old_expected: hunk.old_count,
                        old_actual,
                        new_expected: hunk.new_count,
                        new_actual,
                    });
                }
            }
        }

        Ok(Self { files })
    }

    /// Total de linhas adicionadas.
    #[must_use]
    pub fn additions(&self) -> usize {
        self.files
            .iter()
            .flat_map(|f| &f.hunks)
            .flat_map(|h| &h.lines)
            .filter(|l| l.kind == LineKind::Added)
            .count()
    }

    /// Total de linhas removidas.
    #[must_use]
    pub fn deletions(&self) -> usize {
        self.files
            .iter()
            .flat_map(|f| &f.hunks)
            .flat_map(|h| &h.lines)
            .filter(|l| l.kind == LineKind::Removed)
            .count()
    }
}

fn flush_hunk(hunk: &mut Option<Hunk>, file: &mut Option<FileDiff>) {
    if let Some(h) = hunk.take() {
        if let Some(f) = file.as_mut() {
            f.hunks.push(h);
        }
    }
}

fn parse_hunk_header(s: &str) -> Option<(usize, usize, usize, usize)> {
    let inner = s.strip_prefix("@@ ")?.split(" @@").next()?;
    let mut parts = inner.split_whitespace();
    let old = parts.next()?.strip_prefix('-')?;
    let new = parts.next()?.strip_prefix('+')?;
    let (os, oc) = split_range(old)?;
    let (ns, nc) = split_range(new)?;
    Some((os, oc, ns, nc))
}

fn split_range(s: &str) -> Option<(usize, usize)> {
    match s.split_once(',') {
        Some((a, b)) => Some((a.parse().ok()?, b.parse().ok()?)),
        None => Some((s.parse().ok()?, 1)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
diff --git a/src/lib.rs b/src/lib.rs
index 1234567..89abcde 100644
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,4 @@
 fn main() {
-    println!(\"old\");
+    println!(\"new\");
+    println!(\"extra\");
 }
";

    #[test]
    fn inv_cr_02_empty_diff_rejected() {
        assert!(matches!(Diff::parse(""), Err(DiffError::Empty)));
        assert!(matches!(Diff::parse("   \n"), Err(DiffError::Empty)));
        assert!(matches!(Diff::parse("\n\n"), Err(DiffError::Empty)));
    }

    #[test]
    fn parse_simple_diff() {
        let d = Diff::parse(SAMPLE).unwrap();
        assert_eq!(d.files.len(), 1);
        assert_eq!(d.files[0].new_path, "src/lib.rs");
        assert_eq!(d.additions(), 2);
        assert_eq!(d.deletions(), 1);
    }

    #[test]
    fn inv_cr_11_hunk_count_mismatch_rejected() {
        let bad = "diff --git a/x.rs b/x.rs\n@@ -1,5 +1,5 @@\n+x\n";
        assert!(matches!(
            Diff::parse(bad),
            Err(DiffError::HunkCountMismatch { .. })
        ));
    }

    #[test]
    fn invalid_hunk_header_rejected() {
        let bad = "diff --git a/x.rs b/x.rs\n@@ malformed @@\n+x\n";
        assert!(matches!(
            Diff::parse(bad),
            Err(DiffError::InvalidHunkHeader { .. })
        ));
    }

    #[test]
    fn malformed_diff_git_line_rejected() {
        let bad = "diff --git only_one_part\n";
        assert!(matches!(Diff::parse(bad), Err(DiffError::Malformed { .. })));
    }

    #[test]
    fn hunk_with_no_count_shorthand() {
        // `@@ -1 +1 @@` significa old_count=1, new_count=1
        let d = "diff --git a/x.rs b/x.rs\n@@ -1 +1 @@\n-old\n+new\n";
        let parsed = Diff::parse(d).unwrap();
        assert_eq!(parsed.files[0].hunks[0].old_count, 1);
        assert_eq!(parsed.files[0].hunks[0].new_count, 1);
    }

    #[test]
    fn multiple_files_parsed() {
        let input = "\
diff --git a/a.rs b/a.rs
@@ -1,1 +1,1 @@
-a
+b
diff --git a/b.rs b/b.rs
@@ -1,1 +1,1 @@
-c
+d
";
        let d = Diff::parse(input).unwrap();
        assert_eq!(d.files.len(), 2);
        assert_eq!(d.files[0].new_path, "a.rs");
        assert_eq!(d.files[1].new_path, "b.rs");
    }

    #[test]
    fn multiple_hunks_per_file() {
        let input = "\
diff --git a/x.rs b/x.rs
@@ -1,1 +1,1 @@
-a
+b
@@ -10,1 +10,1 @@
-c
+d
";
        let d = Diff::parse(input).unwrap();
        assert_eq!(d.files[0].hunks.len(), 2);
        assert_eq!(d.files[0].hunks[0].old_start, 1);
        assert_eq!(d.files[0].hunks[1].old_start, 10);
    }

    #[test]
    fn context_lines_preserved() {
        let input = "\
diff --git a/x.rs b/x.rs
@@ -1,3 +1,3 @@
 fn foo() {
-    old();
+    new();
 }
";
        let d = Diff::parse(input).unwrap();
        let hunk = &d.files[0].hunks[0];
        assert_eq!(hunk.lines.len(), 4);
        assert_eq!(hunk.lines[0].kind, LineKind::Context);
        assert_eq!(hunk.lines[1].kind, LineKind::Removed);
        assert_eq!(hunk.lines[2].kind, LineKind::Added);
        assert_eq!(hunk.lines[3].kind, LineKind::Context);
    }

    #[test]
    fn line_numbers_are_correct() {
        let d = Diff::parse(SAMPLE).unwrap();
        let hunk = &d.files[0].hunks[0];
        // Primeira linha de contexto no ficheiro antigo = 1, novo = 1
        assert_eq!(hunk.lines[0].old_line, Some(1));
        assert_eq!(hunk.lines[0].new_line, Some(1));
        // Linha removida — só tem old_line
        assert_eq!(hunk.lines[1].old_line, Some(2));
        assert_eq!(hunk.lines[1].new_line, None);
        // Linha adicionada — só tem new_line
        assert_eq!(hunk.lines[2].old_line, None);
        assert_eq!(hunk.lines[2].new_line, Some(2));
    }
}
