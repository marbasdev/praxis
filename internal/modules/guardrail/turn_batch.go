package guardrail

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"praxis/internal/domain"
	"praxis/internal/infra/git"
)

const (
	maxTurnBaselineBytes    = 128 * 1024
	maxStopReverifyAttempts = 2
	maxStopDisplayFiles     = 8
)

type pendingTurnEdit struct {
	SessionID       string
	Scope           string
	FilePath        string
	RepoDir         string
	TurnInput       string
	BaselineExists  int
	BaselineContent string
	FallbackSnippet string
}

func resolveCanonicalToolPath(rawPath, repoDir, cwd string) string {
	p := strings.TrimSpace(rawPath)
	if p == "" {
		return ""
	}
	if !filepath.IsAbs(p) {
		if base := domain.FirstNonEmpty(repoDir, cwd); base != "" {
			p = filepath.Join(base, p)
		}
	}
	return filepath.Clean(p)
}

func captureFileBaseline(path string) (exists int, content string) {
	if strings.HasPrefix(path, "_unnamed:") {
		return -1, ""
	}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return 0, ""
	}
	if err != nil || len(data) > maxTurnBaselineBytes || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return -1, ""
	}
	return 1, string(data)
}

func (s *Service) recordPendingTurnEdit(ctx context.Context, sid, scope, repoDir, toolName string, ev NormalizedHookEvent, snippet string) {
	sid = domain.ScopedSessionID(ctx, sid)
	if strings.TrimSpace(sid) == "" || s.db == nil {
		return
	}
	sc := domain.NormalizeScope(scope)
	targetPath := resolveCanonicalToolPath(ev.TargetPath, repoDir, ev.Cwd)
	if targetPath == "" {
		targetPath = "_unnamed:" + strings.ToLower(strings.TrimSpace(toolName))
	}

	var turnInp string
	if ev.SessionID != "" {
		turnInp = s.mem.ActiveTurnInput(ctx, ev.SessionID, sc)
	}
	turnInp = domain.FirstNonEmpty(turnInp, ev.TurnPrompt)

	now := time.Now().Unix()
	s.clearStalePendingTurnEdits(ctx, sid, turnInp)

	baselineExists, baselineContent := captureFileBaseline(targetPath)
	fallbackSnippet := ""
	if baselineExists == -1 {
		fallbackSnippet = domain.TruncateUTF8Bytes(strings.TrimSpace(snippet), maxTurnFallbackSnippetBytes)
	}

	_, _ = s.db.ExecContext(ctx, `
		INSERT INTO turn_pending_edits (
			session_id, scope, file_path, repo_dir, turn_input,
			baseline_exists, baseline_content, fallback_snippet, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(session_id, scope, file_path) DO UPDATE SET
			updated_at = excluded.updated_at,
			repo_dir = CASE WHEN excluded.repo_dir != '' THEN excluded.repo_dir ELSE turn_pending_edits.repo_dir END,
			turn_input = CASE WHEN excluded.turn_input != '' THEN excluded.turn_input ELSE turn_pending_edits.turn_input END,
			fallback_snippet = CASE
				WHEN turn_pending_edits.baseline_exists = -1 AND excluded.fallback_snippet != '' THEN
					CASE
						WHEN turn_pending_edits.fallback_snippet = '' THEN excluded.fallback_snippet
						ELSE substr(turn_pending_edits.fallback_snippet || char(10) || excluded.fallback_snippet, 1, 16000)
					END
				ELSE turn_pending_edits.fallback_snippet
			END
	`, sid, sc, targetPath, strings.TrimSpace(repoDir), turnInp, baselineExists, baselineContent, fallbackSnippet, now)

	_, _ = s.db.ExecContext(ctx, `DELETE FROM turn_pending_edits WHERE updated_at < ?`, now-7200)
}

func (s *Service) clearPreviousTurnEdits(ctx context.Context, rawSID, turnInput string) {
	sid := domain.ScopedSessionID(ctx, rawSID)
	inp := strings.TrimSpace(turnInput)
	if sid == "" || inp == "" || s.db == nil {
		return
	}
	res, err := s.db.ExecContext(ctx,
		`DELETE FROM turn_pending_edits WHERE session_id = ? AND turn_input != ?`,
		sid, inp)
	if err == nil {
		if n, _ := res.RowsAffected(); n > 0 && s.mem != nil {
			s.mem.ClearTurnStopRetries(ctx, sid)
		}
	}
}

func (s *Service) clearStalePendingTurnEdits(ctx context.Context, rawSID, turnInput string) {
	sid := domain.ScopedSessionID(ctx, rawSID)
	inp := strings.TrimSpace(turnInput)
	if sid == "" || inp == "" || s.db == nil {
		return
	}
	_, _ = s.db.ExecContext(ctx,
		`DELETE FROM turn_pending_edits WHERE session_id = ? AND turn_input != '' AND turn_input != ?`,
		sid, inp)
}

func (s *Service) clearPendingTurnEdits(ctx context.Context, sid string) {
	sid = domain.ScopedSessionID(ctx, sid)
	if strings.TrimSpace(sid) == "" || s.db == nil {
		return
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM turn_pending_edits WHERE session_id = ?`, sid)
}

func (s *Service) clearPendingTurnEditsForScope(ctx context.Context, sid, rawScope string) {
	sid = domain.ScopedSessionID(ctx, sid)
	if strings.TrimSpace(sid) == "" || s.db == nil {
		return
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM turn_pending_edits WHERE session_id = ? AND scope = ?`, sid, domain.NormalizeScope(rawScope))
}

func (s *Service) loadPendingTurnEdits(ctx context.Context, sid string) ([]pendingTurnEdit, error) {
	sid = domain.ScopedSessionID(ctx, sid)
	if strings.TrimSpace(sid) == "" || s.db == nil {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT session_id, scope, file_path, repo_dir, turn_input, baseline_exists, baseline_content, fallback_snippet
		FROM turn_pending_edits
		WHERE session_id = ?
		ORDER BY updated_at ASC, file_path ASC
	`, sid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []pendingTurnEdit
	for rows.Next() {
		var e pendingTurnEdit
		if err := rows.Scan(&e.SessionID, &e.Scope, &e.FilePath, &e.RepoDir, &e.TurnInput, &e.BaselineExists, &e.BaselineContent, &e.FallbackSnippet); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func displayEditPath(filePath, repoDir, fallbackCwd string, multiRoot bool) string {
	if repoDir != "" && filepath.IsAbs(filePath) {
		cleanRepo := filepath.Clean(repoDir)
		if rel, err := filepath.Rel(cleanRepo, filePath); err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
			slashed := filepath.ToSlash(rel)
			needPrefix := multiRoot
			if !needPrefix && fallbackCwd != "" {
				cleanCwd := filepath.Clean(fallbackCwd)
				if cleanCwd != cleanRepo && !strings.HasPrefix(cleanCwd, cleanRepo+string(filepath.Separator)) {
					needPrefix = true
				}
			}
			if needPrefix {
				if base := filepath.Base(cleanRepo); base != "" && base != "." && base != string(filepath.Separator) {
					return base + "/" + slashed
				}
			}
			return slashed
		}
	}
	if fallbackCwd != "" && filepath.IsAbs(filePath) {
		if rel, err := filepath.Rel(filepath.Clean(fallbackCwd), filePath); err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(filePath)
}

func diffPendingTurnEdit(ctx context.Context, e pendingTurnEdit, displayPath string) string {
	fallback := func() string {
		if e.FallbackSnippet == "" {
			return ""
		}
		return fmt.Sprintf("File: %s\n%s", displayPath, e.FallbackSnippet)
	}
	if strings.HasPrefix(e.FilePath, "_unnamed:") {
		return fallback()
	}
	data, err := os.ReadFile(e.FilePath)
	if os.IsNotExist(err) {
		if e.RepoDir != "" {
			if _, rootErr := os.Stat(e.RepoDir); os.IsNotExist(rootErr) {
				return ""
			}
		}
		if e.BaselineExists == 1 && strings.TrimSpace(e.BaselineContent) != "" {
			return fmt.Sprintf("File: %s (deleted)\nRemoved:\n%s", displayPath, domain.CompactDiffLine(e.BaselineContent, maxTurnFallbackSnippetBytes))
		}
		return ""
	}
	if err != nil {
		return fallback()
	}

	if e.BaselineExists == -1 {
		if e.RepoDir != "" {
			if gDiff := strings.TrimSpace(git.DiffFile(ctx, e.RepoDir, e.FilePath)); gDiff != "" {
				compacted, wsOnly := domain.CompactUnifiedDiffBody(gDiff)
				if wsOnly {
					return fmt.Sprintf("File: %s %s", displayPath, compacted)
				}
				if compacted != "" {
					return fmt.Sprintf("File: %s\n%s", displayPath, compacted)
				}
			}
		}
		return fallback()
	}

	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		if f := fallback(); f != "" {
			return f
		}
		return fmt.Sprintf("File: %s (binary file modified)", displayPath)
	}

	cur := string(data)
	if e.BaselineExists == 1 && cur == e.BaselineContent {
		return ""
	}
	oldText := e.BaselineContent
	if e.BaselineExists == 0 {
		oldText = ""
	}
	diff := domain.FormatChangedLineHunks(oldText, cur, 0)
	if strings.TrimSpace(diff) == "" {
		return ""
	}
	if diff == "(whitespace/formatting only)" {
		return fmt.Sprintf("File: %s %s", displayPath, diff)
	}
	return fmt.Sprintf("File: %s\n%s", displayPath, diff)
}

func formatBatchToolLabel(n int) string {
	if n == 1 {
		return "turn-batch (1 file)"
	}
	return fmt.Sprintf("turn-batch (%d files)", n)
}

type stopScopeBatch struct {
	scope string
	edits []pendingTurnEdit
}

func groupPendingEditsByScope(edits []pendingTurnEdit) []stopScopeBatch {
	scopeIdx := make(map[string]int)
	var batches []stopScopeBatch
	for _, e := range edits {
		idx, ok := scopeIdx[e.Scope]
		if !ok {
			idx = len(batches)
			scopeIdx[e.Scope] = idx
			batches = append(batches, stopScopeBatch{scope: e.Scope})
		}
		batches[idx].edits = append(batches[idx].edits, e)
	}
	return batches
}

func (s *Service) runStopHook(ctx context.Context, ev NormalizedHookEvent, codec AgentCodec, sid, fallbackCwd string) (string, int, error) {
	persistCtx, persistCancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer persistCancel()

	if tr := strings.ToUpper(strings.TrimSpace(ev.Raw.TerminationReason)); tr != "" && tr != "NO_TOOL_CALL" {
		s.clearPendingTurnEdits(persistCtx, sid)
		s.mem.ClearTurnStopRetries(persistCtx, sid)
		return codec.FormatEmpty()
	}

	type stopDiffBatch struct {
		scope     string
		turnInput string
		sections  []fileDiffSection
	}
	var diffBatches []stopDiffBatch
	touchedFiles := []string{}
	seenTouched := make(map[string]bool)
	cwd := domain.FirstNonEmpty(ev.Cwd, fallbackCwd)

	if ev.ClientCtx != nil && (ev.ClientCtx.RemoteManagedEdit || len(ev.ClientCtx.DiffSections) > 0) {
		byScope := make(map[string]int)
		defaultSc := domain.FirstNonEmpty(ev.ClientCtx.TargetScope, ev.Scope, "global")
		for _, ds := range ev.ClientCtx.DiffSections {
			if strings.TrimSpace(ds.Body) == "" {
				continue
			}
			sc := domain.NormalizeScope(domain.FirstNonEmpty(ds.Scope, defaultSc))
			idx, ok := byScope[sc]
			if !ok {
				idx = len(diffBatches)
				byScope[sc] = idx
				diffBatches = append(diffBatches, stopDiffBatch{scope: sc})
			}
			diffBatches[idx].sections = append(diffBatches[idx].sections, fileDiffSection{Label: ds.Label, Body: ds.Body})
			if ds.Label != "" && !seenTouched[ds.Label] {
				seenTouched[ds.Label] = true
				touchedFiles = append(touchedFiles, ds.Label)
			}
		}
	} else {
		edits, err := s.loadPendingTurnEdits(ctx, sid)
		if err != nil || len(edits) == 0 {
			s.mem.ClearTurnStopRetries(persistCtx, sid)
			return codec.FormatEmpty()
		}
		scopeBatches := groupPendingEditsByScope(edits)
		distinctRoots := make(map[string]bool)
		for _, e := range edits {
			if r := strings.TrimSpace(e.RepoDir); r != "" {
				distinctRoots[filepath.Clean(r)] = true
			}
		}
		multiRoot := len(scopeBatches) > 1 || len(distinctRoots) > 1
		for _, b := range scopeBatches {
			var sections []fileDiffSection
			scopeTurnInput := ""
			for _, e := range b.edits {
				if scopeTurnInput == "" && e.TurnInput != "" {
					scopeTurnInput = e.TurnInput
				}
				label := displayEditPath(e.FilePath, e.RepoDir, cwd, multiRoot)
				diff := diffPendingTurnEdit(ctx, e, label)
				if diff == "" {
					continue
				}
				sections = append(sections, fileDiffSection{Label: label, Body: diff})
				if !seenTouched[label] {
					seenTouched[label] = true
					touchedFiles = append(touchedFiles, label)
				}
			}
			if len(sections) > 0 {
				diffBatches = append(diffBatches, stopDiffBatch{scope: b.scope, turnInput: scopeTurnInput, sections: sections})
			} else {
				s.clearPendingTurnEditsForScope(persistCtx, sid, b.scope)
			}
		}
	}

	if len(diffBatches) == 0 {
		s.clearPendingTurnEdits(persistCtx, sid)
		s.mem.ClearTurnStopRetries(persistCtx, sid)
		return codec.FormatEmpty()
	}

	curRetry := s.mem.MaxTurnStopRetry(ctx, sid)
	if (ev.Raw.ContinuationActive || ev.Raw.StopHookActive) && curRetry <= 0 {
		s.clearPendingTurnEdits(persistCtx, sid)
		return codec.FormatEmpty()
	}
	atRetryCap := curRetry >= maxStopReverifyAttempts

	var allBlocking []domain.PlanViolation
	var violatingFiles []string
	seenViolatingFiles := make(map[string]bool)
	var failClosedScopes []string
	var partialDetails []string
	var blockingScopes []string

	for i, b := range diffBatches {
		if i > 0 {
			expired := ctx.Err() != nil
			if !expired {
				if dl, ok := ctx.Deadline(); ok && time.Until(dl) < stopChunkMinRemainingTime {
					expired = true
				}
			}
			if expired {
				var remLabels []string
				seenRem := make(map[string]bool)
				for _, rem := range diffBatches[i:] {
					for _, sec := range rem.sections {
						remLabels = appendUniqueLabel(remLabels, seenRem, sec.Label)
					}
				}
				failClosed := os.Getenv("PRAXIS_GUARDRAIL_FAIL_CLOSED") == "1"
				compactRem := formatCompactFileList(remLabels, maxStopDisplayFiles)
				note := fmt.Sprintf("unreached scopes (%s)", compactRem)
				if failClosed && !atRetryCap {
					failClosedScopes = append(failClosedScopes, b.scope)
					partialDetails = append(partialDetails, note)
				} else {
					partialDetails = append(partialDetails, note)
					if (len(allBlocking) == 0 && len(failClosedScopes) == 0) || atRetryCap {
						s.mem.SetTurnPartialNotice(persistCtx, sid, b.scope, fmt.Sprintf(
							"[PRAXIS GUARDRAIL NOTICE] Previous turn diff exceeded Stop hook time budget across multiple scopes. Unverified files: %s — keep changes in smaller units or run verify_plan_against_memory / git pre-commit.",
							compactRem,
						))
					}
				}
				break
			}
		}

		blocking, vFiles, failClosed, partialMsg := s.verifyStopDiffSections(ctx, persistCtx, ev, sid, b.scope, b.turnInput, b.sections, atRetryCap)
		if len(blocking) > 0 {
			allBlocking = mergeStopViolations(allBlocking, blocking)
			blockingScopes = append(blockingScopes, b.scope)
			for _, f := range vFiles {
				violatingFiles = appendUniqueLabel(violatingFiles, seenViolatingFiles, f)
			}
		} else if failClosed {
			failClosedScopes = append(failClosedScopes, b.scope)
		} else if partialMsg == "" {
			s.clearPendingTurnEditsForScope(persistCtx, sid, b.scope)
		}
		if partialMsg != "" {
			partialDetails = append(partialDetails, partialMsg)
		}
	}

	if len(allBlocking) == 0 && len(failClosedScopes) == 0 {
		s.clearPendingTurnEdits(persistCtx, sid)
		s.mem.ClearTurnStopRetries(persistCtx, sid)
		return codec.FormatEmpty()
	}
	if atRetryCap {
		s.clearPendingTurnEdits(persistCtx, sid)
		s.mem.ClearTurnStopRetries(persistCtx, sid)
		return codec.FormatEmpty()
	}
	retryScopes := blockingScopes
	if len(retryScopes) == 0 {
		retryScopes = failClosedScopes
	}
	for _, sc := range retryScopes {
		s.mem.SetTurnStopRetry(persistCtx, sid, sc, curRetry+1)
	}
	reportFiles := violatingFiles
	if len(reportFiles) == 0 {
		reportFiles = touchedFiles
	}
	return codec.FormatStopContinue(formatStopBlockingMessage(allBlocking, failClosedScopes, partialDetails, reportFiles))
}

func mergeStopViolations(existing, incoming []domain.PlanViolation) []domain.PlanViolation {
	if len(incoming) == 0 {
		return existing
	}
	keyOf := func(v domain.PlanViolation) string {
		if v.ID != 0 {
			return fmt.Sprintf("id:%d", v.ID)
		}
		return fmt.Sprintf("rule:%s|%s|%s", v.Scope, v.Category, v.Content)
	}
	byKey := make(map[string]domain.PlanViolation, len(existing)+len(incoming))
	for _, v := range existing {
		byKey[keyOf(v)] = v
	}
	for _, v := range incoming {
		k := keyOf(v)
		if prev, ok := byKey[k]; ok {
			if !prev.RequiresConfirm {
				v.RequiresConfirm = false
			}
			if prev.Probability > v.Probability {
				v.Probability = prev.Probability
			}
			if prev.Confidence > v.Confidence {
				v.Confidence = prev.Confidence
			}
		}
		byKey[k] = v
	}
	merged := make([]domain.PlanViolation, 0, len(byKey))
	for _, v := range byKey {
		merged = append(merged, v)
	}
	return filterAndSortViolations(merged, 0)
}

func formatCompactFileList(files []string, limit int) string {
	if len(files) == 0 {
		return ""
	}
	if limit <= 0 || len(files) <= limit {
		return strings.Join(files, ", ")
	}
	return fmt.Sprintf("%s (+%d more)", strings.Join(files[:limit], ", "), len(files)-limit)
}

func (s *Service) verifyStopDiffSections(
	ctx context.Context,
	persistCtx context.Context,
	ev NormalizedHookEvent,
	sid, scope, scopeTurnInput string,
	sections []fileDiffSection,
	atRetryCap bool,
) ([]domain.PlanViolation, []string, bool, string) {
	if len(sections) == 0 {
		return nil, nil, false, ""
	}

	evalEvent := ev
	if evalEvent.TurnPrompt == "" && scopeTurnInput != "" {
		evalEvent.TurnPrompt = scopeTurnInput
	}
	if evalEvent.SessionID == "" {
		evalEvent.SessionID = sid
	}

	buildChunks := func(budget int) []diffPlanChunk {
		return packDiffChunks(func(_, _ int, labels []string) string {
			return fmt.Sprintf("Turn edited files (%s):\n", strings.Join(labels, ", "))
		}, sections, budget)
	}
	toolLabel := formatBatchToolLabel(len(sections))
	start := time.Now()
	res := s.evaluateGuardrailPlanChunks(ctx, buildChunks, evalEvent, scope, 0.80, true)
	elapsedMs := domain.ElapsedMsSince(start)

	if res.VerifyErr != nil {
		if atRetryCap {
			failClosed := os.Getenv("PRAXIS_GUARDRAIL_FAIL_CLOSED") == "1"
			_, _ = s.RecordGuardrailLog(persistCtx, domain.GuardrailLogInput{
				Scope:       scope,
				Source:      ev.Mode,
				ToolName:    toolLabel,
				Verdict:     domain.GuardrailVerdictError,
				Blocked:     false,
				RuleCount:   res.RuleCount,
				PlanSnippet: res.CombinedSnippet,
				Details:     res.VerifyErr.Error() + " (Stop retry cap reached — yielded)",
				ElapsedMs:   elapsedMs,
			})
			if failClosed {
				s.mem.SetTurnPartialNotice(persistCtx, sid, scope, fmt.Sprintf(
					"[PRAXIS GUARDRAIL NOTICE] Stop re-verification limit reached (%d retries) with evaluation error (%s); run verify_plan_against_memory or git pre-commit before committing.",
					maxStopReverifyAttempts, res.VerifyErr.Error(),
				))
				return nil, nil, true, ""
			}
			return nil, nil, false, ""
		}
		failClosed := s.recordVerifyOutcomeLog(persistCtx, scope, ev.Mode, toolLabel, res.RuleCount, res.CombinedSnippet, nil, res.VerifyErr, elapsedMs)
		return nil, nil, failClosed, ""
	}
	if len(res.Blocking) > 0 {
		if atRetryCap {
			vIDs, vDetails := formatViolationDetails(res.Blocking)
			_, _ = s.RecordGuardrailLog(persistCtx, domain.GuardrailLogInput{
				Scope:       scope,
				IsPrivate:   res.HasPersonalViolation,
				Source:      ev.Mode,
				ToolName:    toolLabel,
				Verdict:     domain.GuardrailVerdictRuleViolation,
				Blocked:     false,
				RuleCount:   res.RuleCount,
				ViolatedIDs: vIDs,
				PlanSnippet: res.CombinedSnippet,
				Details:     vDetails + "\n[Stop retry cap reached — yielded to prevent loop]",
				ElapsedMs:   elapsedMs,
			})
			s.mem.SetTurnPartialNotice(persistCtx, sid, scope, fmt.Sprintf(
				"[PRAXIS GUARDRAIL NOTICE] Stop re-verification limit reached (%d retries) with unresolved rule violations — resolve before committing:\n%s",
				maxStopReverifyAttempts, vDetails,
			))
			return res.Blocking, res.ViolatingFiles, false, ""
		}
		s.recordVerifyOutcomeLog(persistCtx, scope, ev.Mode, toolLabel, res.RuleCount, res.CombinedSnippet, res.Blocking, nil, elapsedMs)
		partialNote := ""
		if res.Partial && len(res.UnverifiedFiles) > 0 {
			partialNote = fmt.Sprintf("%s (%d/%d chunks verified; unreached: %s)", scope, res.EvaluatedChunks, res.TotalChunks, formatCompactFileList(res.UnverifiedFiles, maxStopDisplayFiles))
		}
		return res.Blocking, res.ViolatingFiles, false, partialNote
	}
	if res.Partial {
		failClosed := os.Getenv("PRAXIS_GUARDRAIL_FAIL_CLOSED") == "1"
		compactUnverified := formatCompactFileList(res.UnverifiedFiles, maxStopDisplayFiles)
		detail := fmt.Sprintf("Evaluated %d/%d diff chunks within Stop hook budget; unverified files: %s",
			res.EvaluatedChunks, res.TotalChunks, compactUnverified)
		_, _ = s.RecordGuardrailLog(persistCtx, domain.GuardrailLogInput{
			Scope:       scope,
			Source:      ev.Mode,
			ToolName:    toolLabel,
			Verdict:     domain.GuardrailVerdictPartial,
			Blocked:     failClosed && !atRetryCap,
			RuleCount:   res.RuleCount,
			PlanSnippet: res.CombinedSnippet,
			Details:     detail,
			ElapsedMs:   elapsedMs,
		})
		if failClosed && !atRetryCap {
			return nil, nil, true, fmt.Sprintf("%s (%d/%d chunks verified; unverified: %s)",
				scope, res.EvaluatedChunks, res.TotalChunks, compactUnverified)
		}
		s.mem.SetTurnPartialNotice(persistCtx, sid, scope, fmt.Sprintf(
			"[PRAXIS GUARDRAIL NOTICE] Previous turn diff exceeded Stop hook time budget (%d/%d chunks verified). Unverified files: %s — keep changes in smaller units or run verify_plan_against_memory / git pre-commit.",
			res.EvaluatedChunks, res.TotalChunks, compactUnverified,
		))
		return nil, nil, false, ""
	}
	s.recordVerifyOutcomeLog(persistCtx, scope, ev.Mode, toolLabel, res.RuleCount, res.CombinedSnippet, nil, nil, elapsedMs)
	return nil, nil, false, ""
}

func formatStopBlockingMessage(allBlocking []domain.PlanViolation, failClosedScopes, partialDetails, touchedFiles []string) string {
	var sb strings.Builder
	if len(allBlocking) > 0 {
		sb.WriteString("[PRAXIS GUARDRAIL — FIX BEFORE FINISHING] Your file edits in this turn violate active project rules:\n")
		for _, v := range allBlocking {
			fmt.Fprintf(&sb, "- [%s / %s %s] %s (violation prob: %.0f%%)\n",
				v.Scope, v.Category, formatViolationRef(v.Fact), v.Content, v.Probability*100)
		}
		if len(touchedFiles) > 0 {
			fmt.Fprintf(&sb, "Touched files: %s\n", formatCompactFileList(touchedFiles, maxStopDisplayFiles))
		}
		if len(partialDetails) > 0 {
			fmt.Fprintf(&sb, "Partial budget note: %s\n", strings.Join(partialDetails, "; "))
		}
		if len(failClosedScopes) > 0 {
			fmt.Fprintf(&sb, "Fail-closed scopes: %s\n", strings.Join(failClosedScopes, ", "))
		}
		sb.WriteString("Fix the violating edits directly in those files before ending your response (only update/forget a rule if the user already approved superseding it; otherwise revert/comply now and ask the user to revise that #ID).")
	} else if len(partialDetails) > 0 {
		fmt.Fprintf(&sb, "[PRAXIS GUARDRAIL — FIX BEFORE FINISHING] Stop batch verification exceeded hook time budget under fail-closed policy: %s", strings.Join(partialDetails, "; "))
	} else {
		fmt.Fprintf(&sb, "[PRAXIS GUARDRAIL — FIX BEFORE FINISHING] Stop batch verification failed under fail-closed policy (%s).", strings.Join(failClosedScopes, ", "))
	}
	return strings.TrimSpace(sb.String())
}
