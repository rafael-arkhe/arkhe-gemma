pub struct Diff {
    pub files: Vec<FileDiff>,
}
pub struct FileDiff {
    pub new_path: String,
    pub hunks: Vec<String>,
}
impl Diff {
    pub fn parse(_text: &str) -> Result<Self, String> {
        Ok(Self {
            files: vec![FileDiff {
                new_path: "dummy".to_string(),
                hunks: vec!["dummy".to_string()],
            }],
        })
    }
}
#[derive(Default)]
pub struct ReviewConfig {
    _priv: (),
}

pub struct ReviewOrchestrator;
impl ReviewOrchestrator {
    pub fn new(_: Vec<()>, _: Vec<()>, _: ReviewConfig) -> Self {
        Self
    }
}
