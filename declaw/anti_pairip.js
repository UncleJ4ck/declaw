'use strict';
// declaw anti-PairIP v2. Loaded via `fritap -c` at spawn (before PairIP's
// JNI_OnLoad / CoreComponentFactory.<clinit> runs). All hook points are libc
// exports (syscall, pthread_create, dl_iterate_phdr, strstr, abort/exit), which
// are ALWAYS present by name even in a stripped libpairipcore.so, because
// stripping never removes .dynsym imports the linker needs. Grounded in RE of
// a real arm64 libpairipcore.so +
// Solaree/pairipcore's published antidebugger() decompile: PairIP forks a child
// that ptrace-attaches the parent to scan memory. The choke point is libc
// syscall() (ptrace is not even imported), so deny ptrace + kill the fork child.
(function () {
  // Frida 17.x removed the two-arg static Module.findExportByName / getExportByName.
  // This script is loaded raw via `fritap -c`, so on a modern friTap every hook below
  // silently no-ops (the try/catch swallows the ReferenceError) and the whole anti-PairIP
  // defense does nothing against exactly the hardened apps it exists for. Restore the
  // two-arg API, the same shim declaw's gadget bundle already ships in bypass.py, ported
  // to plain ES5. Process.findModuleByName is still present on the 17.x line.
  if (!Module.findExportByName) {
    Module.findExportByName = function (m, s) {
      try {
        if (m === null) return (Module.getGlobalExportByName ? Module.getGlobalExportByName(s) : null);
        var mod = Process.findModuleByName(m);
        return mod ? mod.findExportByName(s) : null;
      } catch (e) { return null; }
    };
  }
  if (!Module.getExportByName) {
    Module.getExportByName = function (m, s) {
      if (m === null) return Module.getGlobalExportByName(s);
      var mod = Process.findModuleByName(m);
      if (!mod) throw new Error('anti-pairip: module not found: ' + m);
      return mod.getExportByName(s);
    };
  }

  var KILL_WATCHDOG_THREAD = false; // flip only if the app doesn't hang with it on

  function log(msg) { try { console.log(msg); } catch (e) {} try { send(msg); } catch (e) {} }
  function hook(mod, name, cb) {
    try { var p = Module.findExportByName(mod, name); if (p) cb(p); } catch (e) {}
  }
  function fromPairip(addr) {
    try { var m = Process.findModuleByAddress(addr); return !!m && m.name.toLowerCase() === 'libpairipcore.so'; }
    catch (e) { return false; }
  }
  function pairipModule() { try { return Process.findModuleByName('libpairipcore.so'); } catch (e) { return null; } }

  var BAD = ['frida', 'gadget', 'gum-js', 'gmain', 'gdbus', 'linjector', 'dsvc',
             'xposed', 'magisk', 'substrate', '27042', 're.frida', '/data/local/tmp'];
  function bad(s) {
    if (!s) return false;
    s = ('' + s).toLowerCase();
    for (var i = 0; i < BAD.length; i++) if (s.indexOf(BAD[i]) >= 0) return true;
    return false;
  }

  // 1) THE syscall choke point. antidebugger() calls libc syscall() directly for
  //    prctl/clone/ptrace/wait4 instead of named wrappers. Dispatch on the number.
  var NR_PTRACE = 117; // arm64 generic syscall table
  var NR_CLONE = 220;
  hook('libc.so', 'syscall', function (p) {
    Interceptor.attach(p, {
      onEnter: function (args) {
        this.nr = args[0].toInt32();
        if (this.nr === NR_PTRACE) { this.req = args[1].toInt32(); this.pid = args[2].toInt32(); }
        else if (this.nr === NR_CLONE) { this.flags = args[1].toInt32(); }
      },
      onLeave: function (retval) {
        if (this.nr === NR_PTRACE) {
          log('[pairip] ptrace(req=' + this.req + ', pid=' + this.pid + ') -> forced EPERM');
          retval.replace(ptr(-1));
          return;
        }
        if (this.nr === NR_CLONE && this.flags === 0) {
          // clone(flags=0) == real fork(). PairIP forks a child whose only job is
          // to ptrace-scan us. SIGKILL it (ptrace already denied above).
          var childPid = retval.toInt32();
          if (childPid > 0) {
            try {
              var killFn = new NativeFunction(Module.getExportByName('libc.so', 'kill'), 'int', ['int', 'int']);
              killFn(childPid, 9);
            } catch (e) {}
            log('[pairip] fork child pid=' + childPid + ' killed (self-ptrace watchdog)');
          }
        }
      }
    });
  });

  // 2) The background integrity thread (pthread_create with start_routine inside
  //    libpairipcore). Default: leave it running (its syscalls are neutered).
  hook('libc.so', 'pthread_create', function (p) {
    Interceptor.attach(p, {
      onEnter: function (args) {
        var startRoutine = args[2];
        var mod = pairipModule();
        if (mod && startRoutine.compare(mod.base) >= 0 && startRoutine.compare(mod.base.add(mod.size)) < 0) {
          log('[pairip] watchdog thread start_routine @ ' + startRoutine);
          if (KILL_WATCHDOG_THREAD) {
            args[2] = new NativeCallback(function () { return ptr(0); }, 'pointer', ['pointer']);
            log('[pairip] watchdog thread stubbed to a no-op');
          }
        }
      }
    });
  });

  // 3) dl_iterate_phdr map scan (3 call sites in libpairipcore all via this libc
  //    export). Filter frida/gadget entries out of what the app callback sees.
  //    struct dl_phdr_info.dlpi_name is at offset 8 on arm64.
  hook('libc.so', 'dl_iterate_phdr', function (p) {
    Interceptor.attach(p, {
      onEnter: function (args) {
        var realCb = args[0];
        this.wrapped = new NativeCallback(function (infoPtr, size, data) {
          var name = '';
          try { name = infoPtr.add(8).readPointer().readCString() || ''; } catch (e) {}
          if (bad(name)) return 0; // skip this entry, keep iterating
          try {
            var cb = new NativeFunction(realCb, 'int', ['pointer', 'pointer', 'pointer']);
            return cb(infoPtr, size, data);
          } catch (e) { return 0; }
        }, 'int', ['pointer', 'pointer', 'pointer']);
        args[0] = this.wrapped;
      }
    });
  });

  // 4) /proc scans + strstr: strip frida lines / hide our strings. Also zero
  //    TracerPid so a stray tracer slot (or a debug tool) is not visible.
  var HIDE = {};
  ['open', 'openat'].forEach(function (n) {
    hook('libc.so', n, function (p) {
      Interceptor.attach(p, {
        onEnter: function (a) { var i = (n === 'openat') ? 1 : 0; try { this.path = a[i].readCString(); } catch (e) { this.path = ''; } },
        onLeave: function (r) {
          var fd = r.toInt32();
          if (fd > 0 && this.path && this.path.indexOf('/proc/') >= 0 &&
              (this.path.indexOf('maps') >= 0 || this.path.indexOf('status') >= 0 ||
               this.path.indexOf('comm') >= 0 || this.path.indexOf('task') >= 0)) HIDE[fd] = 1;
        }
      });
    });
  });
  hook('libc.so', 'read', function (p) {
    Interceptor.attach(p, {
      onEnter: function (a) { this.fd = a[0].toInt32(); this.buf = a[1]; },
      onLeave: function (r) {
        if (!(this.fd in HIDE)) return;
        var n = r.toInt32(); if (n <= 0) return;
        try {
          var s = this.buf.readUtf8String(n); if (!s) return;
          var kept = s.split('\n').filter(function (l) { return !bad(l); })
                      .map(function (l) { return l.replace(/TracerPid:\s*\d+/, 'TracerPid:\t0'); }).join('\n');
          if (kept.length !== s.length) { this.buf.writeUtf8String(kept + '\0'); r.replace(ptr(kept.length)); }
        } catch (e) {}
      }
    });
  });
  ['strstr', 'strcasestr'].forEach(function (n) {
    hook('libc.so', n, function (p) {
      Interceptor.attach(p, {
        onEnter: function (a) { try { this.needle = a[1].readCString(); } catch (e) { this.needle = ''; } },
        onLeave: function (r) { if (bad(this.needle)) r.replace(ptr(0)); }
      });
    });
  });

  // 5) Kill switch, scoped to libpairipcore's return address (fails open to swallow).
  function guardExit(name, retType, argTypes) {
    var p = Module.findExportByName('libc.so', name);
    if (!p) return;
    try {
      var orig = new NativeFunction(p, retType, argTypes);
      Interceptor.replace(p, new NativeCallback(function () {
        var scoped;
        try { scoped = fromPairip(this.returnAddress); } catch (e) { scoped = true; }
        if (scoped) { log('[pairip] swallowed ' + name + '()'); return; }
        return orig.apply(this, Array.prototype.slice.call(arguments));
      }, retType, argTypes));
    } catch (e) {}
  }
  guardExit('abort', 'void', []);
  guardExit('exit', 'void', ['int']);
  guardExit('_exit', 'void', ['int']);

  // 6) Crash fix: a scan stores into what it assumes is writable memory and faults
  //    on frida's RO pages. Make the page RWX and retry.
  var patchedPages = {};
  try {
    Process.setExceptionHandler(function (d) {
      if (d.type !== 'access-violation' || !d.memory) return false;
      var addr = d.memory.address;
      if (!addr) return false;
      var page = addr.and(ptr('0xfffffffffffff000'));
      var key = page.toString();
      if (patchedPages[key]) return false;
      patchedPages[key] = 1;
      try { Memory.protect(page, 0x1000, 'rwx'); return true; } catch (e) {}
      try { d.context.pc = d.context.pc.add(4); return true; } catch (e) {}
      return false;
    });
  } catch (e) {}

  // 7) Diagnostic only: scan libpairipcore for an inline `svc #0` (none in the RE'd
  //    build; future builds could inline it instead of calling libc syscall()).
  ['dlopen', 'android_dlopen_ext'].forEach(function (name) {
    hook(null, name, function (p) {
      Interceptor.attach(p, {
        onEnter: function (a) { try { this.path = a[0].readCString(); } catch (e) { this.path = ''; } },
        onLeave: function () {
          if (this.path && this.path.indexOf('libpairipcore.so') >= 0) {
            setImmediate(function () {
              var mod = pairipModule();
              if (!mod) return;
              log('[pairip] libpairipcore.so @ ' + mod.base + ' size=' + mod.size);
              try {
                mod.enumerateRanges('r-x').forEach(function (r) {
                  Memory.scanSync(r.base, r.size, '01 00 00 d4').forEach(function (m) {
                    log('[pairip] inline svc#0 @ ' + m.address + ' (diagnostic only)');
                  });
                });
              } catch (e) {}
            });
          }
        }
      });
    });
  });

  log('[anti-pairip v2] armed');
})();
