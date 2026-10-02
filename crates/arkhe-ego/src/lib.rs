pub enum BehaviorSignature {
    RespectsBudget,
    EmitsRecordHash,
}
pub struct IdentityDeclaration {
    pub id: String,
    pub behavior: String,
    pub signature: BehaviorSignature,
    pub contradicts: Vec<String>,
}
pub struct SelfModel;
impl SelfModel {
    pub fn new(_decls: Vec<IdentityDeclaration>, _a: f64, _b: usize) -> Result<Self, String> {
        Ok(Self)
    }
}
#[derive(Default)]
pub struct MonitorConfig {
    _priv: (),
}

#[derive(Default)]
pub struct NullLedger {
    _priv: (),
}

pub struct Ego;
pub struct CycleOutcome {
    pub ide_count: u32,
}
pub struct Action;
impl Action {
    pub fn from_signatures<I: IntoIterator<Item = BehaviorSignature>>(_sigs: I) -> Self {
        Self
    }
}
impl Ego {
    pub fn new(_model: SelfModel, _a: usize, _b: usize, _c: usize, _config: MonitorConfig) -> Result<Self, String> {
        Ok(Self)
    }
    pub fn cycle(&mut self, _action: Action, _data: Vec<u8>, _a: usize, _b: usize, _c: usize, _ledger: &mut NullLedger) -> Result<CycleOutcome, String> {
        Ok(CycleOutcome { ide_count: 0 })
    }
}
