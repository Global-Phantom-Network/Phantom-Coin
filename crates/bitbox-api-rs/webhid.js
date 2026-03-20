export async function jsSleep(ms) {
  await new Promise(resolve => setTimeout(resolve, ms));
}

export function hasWebHID() {
  return !!navigator.hid;
}

class MessageQueue {
  constructor() {
    this.queue = [];
    this.resolvers = [];
  }

  addMessage(msg) {
    if (this.resolvers.length > 0) {
      const resolveFunc = this.resolvers.shift();
      resolveFunc(msg);
    } else {
      this.queue.push(msg);
    }
  }

  getNextMessage() {
    return new Promise((resolve) => {
      if (this.queue.length > 0) {
        const msg = this.queue.shift();
        resolve(msg);
      } else {
        this.resolvers.push(resolve);
      }
    });
  }
}

function insecureBridgeOptInEnabled() {
  try {
    const raw = globalThis?.PHANTOM_ALLOW_INSECURE_BITBOX_BRIDGE;
    if (raw === true) {
      return true;
    }
    if (typeof raw === 'string' && ['1', 'true', 'yes', 'on'].includes(raw.trim().toLowerCase())) {
      return true;
    }
    if (typeof localStorage !== 'undefined') {
      const stored = localStorage.getItem('PHANTOM_ALLOW_INSECURE_BITBOX_BRIDGE');
      if (stored && ['1', 'true', 'yes', 'on'].includes(stored.trim().toLowerCase())) {
        return true;
      }
    }
  } catch (_) {}
  return false;
}

function ensureInsecureBridgeOptIn() {
  if (!insecureBridgeOptInEnabled()) {
    throw new Error('BitBoxBridge is disabled by default. Set PHANTOM_ALLOW_INSECURE_BITBOX_BRIDGE=true explicitly to opt in.');
  }
}

export async function getWebHIDDevice(vendorId, productId, onCloseCb) {
  let device;
  try {
    // Try to get directly the device. This will work without prompting user
    // permission if it has already been validated before on the current website.
    let devices = await navigator.hid.getDevices({filters: [{vendorId, productId}]});
    if (devices.length == 0){
      // If direct access failed, which happen for new websites, ask user
      // confirmation.
      devices = await navigator.hid.requestDevice({filters: [{vendorId, productId}]});
    }
    const d = devices[0];
    // Filter out other products that might be in the list presented by the Browser.
    if (d.productName.includes('BitBox02')) {
      device = d;
    }
  } catch (err) {
    return null;
  }
  if (!device) {
    return null;
  }
  await device.open();

  // This is suboptimal API in WebHID - ideally we want to attach this event only when the above
  // device is disconnected. This way will likely break if multiple devices are connected at the
  // same time.
  navigator.hid.addEventListener('disconnect', event => {
    const disconnectedDevice = event.device;
    if (disconnectedDevice.vendorId === device.vendorId && disconnectedDevice.productId === device.productId) {
      if (onCloseCb) {
        onCloseCb();
        onCloseCb = undefined;
      }
    }
  });

  const msgQueue = new MessageQueue();


  const onInputReport = event => {
    msgQueue.addMessage(new Uint8Array(event.data.buffer));
  };
  device.addEventListener('inputreport', onInputReport);
  return {
    write: bytes => {
      if (!device.opened) {
        console.error('attempted write to a closed HID connection');
        return;
      }
      device.sendReport(0, bytes);
    },
    read: async () => {
      return await msgQueue.getNextMessage();
    },
    close: () => {
      device.close().then(() => {
        device.removeEventListener('inputreport', onInputReport);
        // The disconnect event above is not fired when closing the
        // device, so we manually invoke the callback.
        if (onCloseCb) {
          onCloseCb();
          onCloseCb = undefined;
      }
      });
    },
    valid: () => device.opened,
  };
}

const MAX_BRIDGE_RESPONSE_BYTES = 1024 * 1024; // 1 MiB

async function readBytesLimited(response, maxBytes) {
  if (maxBytes <= 0) {
    throw new Error('Invalid maxBytes');
  }
  const body = response.body;
  if (!body || !body.getReader) {
    // Fallback: no streaming support. Still enforce a post-read limit.
    const buf = await response.arrayBuffer();
    if (buf.byteLength > maxBytes) {
      throw new Error('Bridge response too large.');
    }
    return new Uint8Array(buf);
  }

  const reader = body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      if (total > maxBytes) {
        try { await reader.cancel(); } catch (_) {}
        throw new Error('Bridge response too large.');
      }
      chunks.push(value);
    }
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

async function readJsonLimited(response, maxBytes) {
  const bytes = await readBytesLimited(response, maxBytes);
  const txt = new TextDecoder('utf-8').decode(bytes);
  try {
    return JSON.parse(txt);
  } catch (e) {
    throw new Error('Invalid bridge JSON response.');
  }
}


async function getDevicePath() {
  ensureInsecureBridgeOptIn();
  const attempts = 10;
  for (let i = 0; i < attempts; i++){
    let response;
    let errorMessage;
    try {
      response = await fetch('http://127.0.0.1:8178/api/v1/devices', {
        method: 'GET',
        headers: {},
      })
      if (!response.ok && response.status === 403) {
        errorMessage = 'Origin not whitelisted.';
        throw new Error();
      } else if (!response.ok) {
        errorMessage = 'Unexpected bridge connection error.';
        throw new Error();
      }
    } catch(err) {
      throw new Error(errorMessage ? errorMessage : 'BitBoxBridge not found.');
    }
    const body = await readJsonLimited(response, MAX_BRIDGE_RESPONSE_BYTES);
    const devices = body.devices;
    if (devices.length !== 1) {
      await jsSleep(100);
      continue;
    }
    const devicePath = devices[0].path;
    return devicePath;
  }
  throw new Error('Expected exactly one BitBox02. If one is connected, it might already have an open connection another app. If so, please close the other app first.');
}

export async function getBridgeDevice(onCloseCb) {
  ensureInsecureBridgeOptIn();
  let devicePath = await getDevicePath();
  const socket = new WebSocket('ws://127.0.0.1:8178/api/v1/socket/' + encodeURIComponent(devicePath));
  const msgQueue = new MessageQueue();

  return new Promise((resolve, reject) => {
    socket.binaryType = 'arraybuffer';
    socket.onmessage = event => { msgQueue.addMessage(new Uint8Array(event.data)); };
    socket.onclose = event => {
      if (onCloseCb) {
        onCloseCb();
        onCloseCb = undefined;
      }
    };
    socket.onopen = function (event) {
      resolve({
        write: bytes => {
          if (socket.readyState != WebSocket.OPEN) {
            console.error('attempted write to a closed socket');
            return;
          }
          socket.send(bytes);
        },
        read: async () => {
          return await msgQueue.getNextMessage();
        },
        close: () => socket.close(),
        valid: () => {
          return socket.readyState == WebSocket.OPEN;
        },
      });
    };
    socket.onerror = function(event) {
      reject(new Error('Your BitBox02 is busy.'));
    };
  });
}
