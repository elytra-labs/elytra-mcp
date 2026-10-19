import { useCallback, useRef, useState } from "react";
import { ArrowRight } from "lucide-react";
import { ConsoleShot } from "./ConsoleShot";
import { useScrollProgress } from "./motion/useScrollProgress";

const STEPS = [
  {
    at: 0,
    title: "An explicit run",
    body: "Your orchestrator opens a run with an intent and no grants. Every call that follows is attributed to it.",
  },
  {
    at: 0.2,
    title: "An untrusted read, allowed",
    code: "github.get_issue",
    body: "A classified source read runs. The run now carries untrusted context.",
  },
  {
    at: 0.4,
    title: "A write, held",
    code: "postgres.run_query",
    body: "A sink without an exact grant stops at the boundary. The database is not called.",
  },
  {
    at: 0.6,
    title: "Your decision",
    body: "Review the arguments, lineage, and expiry. Approval binds this call, run, schema, and policy version.",
  },
  {
    at: 0.8,
    title: "One dispatch",
    body: "The integration claims the approval and dispatches once. A replay or changed arguments need a new decision.",
  },
];

/** Scroll-pinned walkthrough: captions on the left, the console in each state on the right. */
export function BoundarySection() {
  const section = useRef<HTMLElement>(null);
  const [step, setStep] = useState(0);
  const onProgress = useCallback((value: number) => {
    let index = 0;
    STEPS.forEach((item, i) => {
      if (value >= item.at) index = i;
    });
    setStep(index);
  }, []);
  useScrollProgress(section, onProgress);

  return (
    <section id="how-it-works" ref={section} className="stack-section">
      <div className="stack-sticky">
        <div className="stack-copy">
          <div className="section-label">
            <span>02 / THE WORKFLOW</span>
            <span>ONE RUN, FIVE MOMENTS</span>
          </div>
          <h2>
            From context
            <br />
            <em>to consequence.</em>
          </h2>
          <ol className="stack-steps">
            {STEPS.map((item, i) => (
              <li key={item.title} className={i === step ? "active" : i < step ? "done" : ""} aria-current={i === step ? "step" : undefined}>
                <span className="stack-index">0{i + 1}</span>
                <div>
                  <h3>{item.title}</h3>
                  {item.code && <code>{item.code}</code>}
                  <p>{item.body}</p>
                </div>
              </li>
            ))}
          </ol>
          <a className="site-text-link stack-link" href="/demo/">
            Step through the walkthrough <ArrowRight size={14} />
          </a>
        </div>
        <div className="stack-stage">
          <ConsoleShot step={step} />
          <div className="stack-meter" aria-hidden="true">
            {STEPS.map((item, i) => (
              <i key={item.title} className={i <= step ? "on" : ""} />
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
