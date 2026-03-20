export type PromSample = {
  name: string;
  labels: Record<string, string>;
  value: number;
};

function parseLabels(s: string): Record<string, string> {
  const out: Record<string, string> = {};
  const parts = s.split(',');
  for (const part of parts) {
    const p = part.trim();
    if (!p) {
      continue;
    }
    const eq = p.indexOf('=');
    if (eq <= 0) {
      continue;
    }
    const k = p.slice(0, eq).trim();
    let v = p.slice(eq + 1).trim();
    if (v.startsWith('"') && v.endsWith('"') && v.length >= 2) {
      v = v.slice(1, -1);
    }
    out[k] = v;
  }
  return out;
}

export function parsePrometheus(text: string): PromSample[] {
  const out: PromSample[] = [];
  const lines = text.split(/\r?\n/);
  for (const line of lines) {
    const s = line.trim();
    if (!s || s.startsWith('#')) {
      continue;
    }

    const sp = s.lastIndexOf(' ');
    if (sp <= 0) {
      continue;
    }

    const left = s.slice(0, sp).trim();
    const right = s.slice(sp + 1).trim();
    const value = Number.parseFloat(right);
    if (!Number.isFinite(value)) {
      continue;
    }

    const brace = left.indexOf('{');
    if (brace >= 0) {
      const end = left.lastIndexOf('}');
      if (end < brace) {
        continue;
      }
      const name = left.slice(0, brace).trim();
      const labelStr = left.slice(brace + 1, end);
      out.push({ name, labels: parseLabels(labelStr), value });
    } else {
      out.push({ name: left, labels: {}, value });
    }
  }
  return out;
}

export function getScalar(samples: PromSample[], name: string): number | null {
  for (const s of samples) {
    if (s.name === name && Object.keys(s.labels).length === 0) {
      return s.value;
    }
  }
  return null;
}

export function getLabeled(samples: PromSample[], name: string, labels: Record<string, string>): number | null {
  outer: for (const s of samples) {
    if (s.name !== name) {
      continue;
    }
    for (const [k, v] of Object.entries(labels)) {
      if (s.labels[k] !== v) {
        continue outer;
      }
    }
    return s.value;
  }
  return null;
}

export function getHistogramBuckets(samples: PromSample[], name: string, labelKey: string): Map<string, number> {
  const out = new Map<string, number>();
  for (const s of samples) {
    if (s.name !== name) {
      continue;
    }
    const key = s.labels[labelKey];
    if (key !== undefined) {
      out.set(key, s.value);
    }
  }
  return out;
}
