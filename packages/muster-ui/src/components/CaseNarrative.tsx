import { Binary, FileWarning, LockKeyhole, ShieldCheck, Sparkles } from "lucide-react";

import { kernelOutcomeTerm } from "../data/plainLanguage";
import type { HeroCaseViewModel, TraceEvent } from "../data/readModel";

/**
 * The claim-to-decision story, in the order it happened.
 *
 * A first-time reader arrives at this case knowing nothing, and the one thing
 * they must not be shown first is the ending. The final Google Cloud execution
 * proof lives in its own Action view for exactly that reason: it is the last
 * beat, and putting it here would reverse the chronology of the case that
 * earned it.
 *
 * Every line below is read off the trace the producer published. Nothing here
 * is a second, prose copy of a fact -- the beats point at events the reader can
 * then open in the trace underneath, and if the artifact ever stops carrying
 * one of them, that beat disappears rather than going stale.
 */
export function CaseNarrative({ model }: { model: HeroCaseViewModel }) {
  const outcome = kernelOutcomeTerm(model.outcome);
  const claim = find(model, "claim");
  const planner = find(model, "planner");
  const boundary = find(model, "boundary");
  const sources = model.events.filter((event) => event.kind === "agent");
  const rebuild = find(model, "rebuild");

  return (
    <section className="case-narrative" aria-label="How this case reached its decision">
      <div className="narrative-heading">
        <span className="section-label">CLAIM → DECISION</span>
        <h2>How {model.subject} reached a proposed {model.action.amount}</h2>
        <p>
          Each step below is an event in the trace underneath. The finished Google Cloud
          execution of this action is a separate proof, in the Action view.
        </p>
      </div>

      <ol className="narrative-beats">
        {claim && (
          <Beat
            icon={<FileWarning size={15} aria-hidden="true" />}
            tone="inert"
            label="WHAT RAVI CLAIMED"
            headline={claim.title}
            detail={`${claim.result}. ${claim.inspector.authorityGrant}.`}
          />
        )}
        {planner && (
          <Beat
            icon={<Binary size={15} aria-hidden="true" />}
            tone="deterministic"
            label="WHAT MUSTER ASKED FOR"
            headline={planner.title}
            detail={planner.inspector.predicates.join(" · ")}
          />
        )}
        {boundary && (
          <Beat
            icon={<LockKeyhole size={15} aria-hidden="true" />}
            tone="denied"
            label="WHY RAW SITE EVIDENCE NEVER CAME TO THE CONTROL PLANE"
            headline={boundary.result}
            detail={boundary.inspector.disclosure}
          />
        )}
        {sources.length > 0 && (
          <Beat
            icon={<Sparkles size={15} aria-hidden="true" />}
            tone="verified"
            label="WHAT SIGNED FACTS ARRIVED INSTEAD"
            headline={sources
              .flatMap((source) => source.inspector.predicates)
              .join(" · ")}
            detail={`${sources.length} authorized sources · source authority verified (Q-12) · the source material stayed where it was.`}
          />
        )}
        {rebuild && (
          <Beat
            icon={<ShieldCheck size={15} aria-hidden="true" />}
            tone="invariant"
            label={`WHY ${model.action.kind} ${model.action.amount} BECAME SAFE TO PROPOSE`}
            headline={`${outcome.plain} — ${outcome.technical}`}
            detail={`${rebuild.summary} Still unknown: ${model.unresolved.join(" · ")}.`}
          />
        )}
      </ol>
    </section>
  );
}

function find(model: HeroCaseViewModel, id: string): TraceEvent | undefined {
  return model.events.find((event) => event.id === id);
}

interface BeatProps {
  icon: React.ReactNode;
  tone: "inert" | "deterministic" | "denied" | "verified" | "invariant";
  label: string;
  headline: string;
  detail: string;
}

function Beat({ icon, tone, label, headline, detail }: BeatProps) {
  return (
    <li className={`narrative-beat ${tone}`}>
      <span className="narrative-beat-icon" aria-hidden="true">{icon}</span>
      <span className="narrative-beat-label">{label}</span>
      <strong>{headline}</strong>
      <p>{detail}</p>
    </li>
  );
}
