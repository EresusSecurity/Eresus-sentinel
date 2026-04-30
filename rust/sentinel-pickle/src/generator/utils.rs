// generator/utils.rs — Helper methods for the Generator

use super::Generator;
use super::state::GenStackValue;

impl Generator {
    pub(super) fn push(&mut self, val: GenStackValue) {
        self.stack.push(val);
    }

    pub(super) fn pop(&mut self) -> Option<GenStackValue> {
        self.stack.pop()
    }

    pub(super) fn peek(&self) -> Option<&GenStackValue> {
        self.stack.last()
    }

    pub(super) fn stack_depth(&self) -> usize {
        self.stack.len()
    }

    pub(super) fn has_mark(&self) -> bool {
        self.stack.iter().any(|v| matches!(v, GenStackValue::Mark))
    }

    pub(super) fn topmost_mark_idx(&self) -> Option<usize> {
        self.stack.iter().rposition(|v| matches!(v, GenStackValue::Mark))
    }

    /// Count items above the topmost mark on the stack.
    #[allow(dead_code)]
    pub(super) fn items_above_mark(&self) -> usize {
        match self.topmost_mark_idx() {
            Some(idx) => self.stack.len() - idx - 1,
            None => 0,
        }
    }

    /// Check if TOS is a string value (needed for STACK_GLOBAL).
    pub(super) fn tos_is_string(&self) -> bool {
        matches!(self.peek(), Some(GenStackValue::String(_)))
    }

    /// Check if TOS-1 is a string value.
    pub(super) fn tos1_is_string(&self) -> bool {
        if self.stack.len() < 2 { return false; }
        matches!(self.stack[self.stack.len() - 2], GenStackValue::String(_))
    }

    /// Check if TOS is a list.
    pub(super) fn tos_is_list(&self) -> bool {
        matches!(self.peek(), Some(GenStackValue::List))
    }

    /// Check if TOS is a dict.
    #[allow(dead_code)]
    pub(super) fn tos_is_dict(&self) -> bool {
        matches!(self.peek(), Some(GenStackValue::Dict))
    }

    /// Check if TOS is a set.
    #[allow(dead_code)]
    pub(super) fn tos_is_set(&self) -> bool {
        matches!(self.peek(), Some(GenStackValue::Set))
    }

    /// Check if TOS is a callable (Global reference).
    pub(super) fn tos_is_callable(&self) -> bool {
        matches!(self.peek(), Some(GenStackValue::Global { .. }))
    }

    /// Next available memo index.
    pub(super) fn next_memo_idx(&self) -> u32 {
        self.next_memo
    }

    /// Record a memo put and bump counter.
    pub(super) fn memo_put(&mut self) {
        self.next_memo += 1;
    }

    /// Whether memo has any entries.
    pub(super) fn has_memo(&self) -> bool {
        self.next_memo > 0
    }
}
