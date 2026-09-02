'use strict';
'require view';
'require form';
'require fs';
'require rpc';
'require poll';
'require ui';
'require uci';

var packageVersion = '@FPTN_VERSION@';

var botLink = '<a href="https://t.me/fptn_bot" target="_blank" ' +
	'rel="noreferrer">@fptn_bot</a>';

var spoofingMethods = [
	[ 'sni-spoofing-chrome-149', 'Chrome 149' ],
	[ 'sni-spoofing-chrome-148', 'Chrome 148' ],
	[ 'sni-spoofing-chrome-147', 'Chrome 147' ],
	[ 'sni-spoofing-chrome-146', 'Chrome 146' ],
	[ 'sni-spoofing-chrome-145', 'Chrome 145' ],
	[ 'sni-spoofing-firefox-151', 'Firefox 151' ],
	[ 'sni-spoofing-firefox-150', 'Firefox 150' ],
	[ 'sni-spoofing-firefox-149', 'Firefox 149' ],
	[ 'sni-spoofing-yandex-26-4', 'Yandex 26.4' ],
	[ 'sni-spoofing-yandex-26-3', 'Yandex 26.3' ],
	[ 'sni-spoofing-yandex-25', 'Yandex 25' ],
	[ 'sni-spoofing-yandex-24', 'Yandex 24' ],
	[ 'sni-spoofing-safari-26-5', 'Safari 26.5' ],
	[ 'sni-spoofing-safari-26-4', 'Safari 26.4' ]
];

var callServiceList = rpc.declare({
	object: 'service',
	method: 'list',
	params: [ 'name' ],
	expect: { '': {} }
});

function serviceInfo() {
	return callServiceList('fptn').then(function (res) {
		try {
			var instance = res['fptn']['instances']['instance1'];
			return { running: instance['running'] === true, pid: instance['pid'] };
		} catch (e) {
			return { running: false };
		}
	}).catch(function () {
		return { running: false };
	});
}

function isRunning() {
	return serviceInfo().then(function (info) {
		return info.running;
	});
}

function tunnelStats(name) {
	return fs.exec('/sbin/ip', [ '-s', 'link', 'show', name ]).then(function (res) {
		var lines = (res.stdout || '').split('\n');
		var stats = {};

		for (var i = 0; i < lines.length - 1; i++) {
			if (lines[i].indexOf('RX:') >= 0)
				stats.rx = lines[i + 1].trim().split(/\s+/)[0];
			if (lines[i].indexOf('TX:') >= 0)
				stats.tx = lines[i + 1].trim().split(/\s+/)[0];
		}
		return stats;
	}).catch(function () {
		return {};
	});
}

function formatBytes(value) {
	var bytes = parseInt(value, 10);
	if (isNaN(bytes))
		return '—';

	var units = [ 'B', 'KiB', 'MiB', 'GiB', 'TiB' ];
	var unit = 0;

	while (bytes >= 1024 && unit < units.length - 1) {
		bytes /= 1024;
		unit++;
	}

	return (unit === 0 ? bytes : bytes.toFixed(2)) + ' ' + units[unit];
}

function hasTunnel() {
	var name = uci.get('fptn', 'config', 'tun_interface_name') || 'tun0';

	return fs.exec('/sbin/ip', [ '-o', 'link', 'show' ]).then(function (res) {
		return (res.stdout || '').indexOf(' ' + name + ':') >= 0;
	}).catch(function () {
		return false;
	});
}

function readLog() {
	return fs.exec('/sbin/logread', [ '-l', '500', '-e', 'fptn' ]).then(function (res) {
		return (res.stdout || '').trim();
	}).catch(function () {
		return '';
	});
}

function logTail(log) {
	return log.split('\n').filter(function (line) {
		return line.indexOf("Can't to read from device") < 0;
	}).slice(-400).join('\n');
}

function restarts(log) {
	var starts = log.split('\n').filter(function (line) {
		return line.indexOf('Application started successfully') >= 0;
	});

	if (!starts.length)
		return '—';

	var since = starts[0].match(/\d+:\d+:\d+/);

	return (starts.length - 1) + (since ? ' since ' + since[0] : '');
}

function listOption(section, tab, name, key, title, description, placeholder) {
	var o = section.taboption(tab, form.TextValue, name, title, description);

	o.rows = 12;
	o.placeholder = placeholder;
	o.rmempty = true;

	o.cfgvalue = function (sid) {
		var value = uci.get('fptn', sid, key);
		return Array.isArray(value) ? value.join('\n') : (value || '');
	};

	o.write = function (sid, value) {
		var items = (value || '').split(/\r?\n/).map(function (line) {
			return line.trim();
		}).filter(function (line) {
			return line.length > 0;
		});
		uci.set('fptn', sid, key, items);
	};

	o.remove = function () {};

	return o;
}

function compareVersions(left, right) {
	var a = String(left).replace(/^v/, '').split('.');
	var b = String(right).replace(/^v/, '').split('.');
	var length = Math.max(a.length, b.length);

	for (var i = 0; i < length; i++) {
		var x = parseInt(a[i], 10) || 0;
		var y = parseInt(b[i], 10) || 0;

		if (x < y)
			return -1;
		if (x > y)
			return 1;
	}

	return 0;
}

function checkUpdate() {
	return fetch('https://api.github.com/repos/fptn-project/fptn/releases/latest')
		.then(function (res) {
			return res.json();
		})
		.then(function (msg) {
			if (!msg || msg.draft || !msg.name)
				return null;

			return compareVersions(packageVersion, msg.name) < 0 ? msg.name : null;
		})
		.catch(function () {
			return null;
		});
}

function diagnose() {
	var tun = uci.get('fptn', 'config', 'tun_interface_name') || 'tun0';

	uci.unload('dhcp');

	return Promise.all([
		isRunning(),
		fs.exec('/sbin/ip', [ '-o', 'link', 'show' ]).catch(function () {
			return {};
		}),
		fs.exec('/sbin/ip', [ '-o', '-4', 'addr', 'show' ]).catch(function () {
			return {};
		}),
		fs.exec('/sbin/ip', [ '-4', 'route', 'show' ]).catch(function () {
			return {};
		}),
		readLog(),
		uci.load('firewall').catch(function () {}),
		uci.load('dhcp').catch(function () {}),
		fs.exec('/bin/ping', [ '-c', '1', '-W', '3', '8.8.8.8' ]).catch(function () {
			return { code: 1 };
		}),
		tunnelStats(tun)
	]).then(function (r) {
		var links = r[1].stdout || '';
		var addrs = r[2].stdout || '';
		var routes = r[3].stdout || '';
		var log = r[4] || '';

		var linkLine = links.split('\n').filter(function (line) {
			return line.indexOf(' ' + tun + ':') >= 0;
		})[0] || '';

		var addrLine = addrs.split('\n').filter(function (line) {
			return line.indexOf(' ' + tun + ' ') >= 0;
		})[0] || '';

		var defaultLine = routes.split('\n').filter(function (line) {
			return line.indexOf('default') === 0;
		})[0] || '';

		var zones = uci.sections('firewall', 'zone').filter(function (zone) {
			return zone.name === 'fptn';
		});

		var dnsmasq = uci.sections('dhcp', 'dnsmasq')[0];
		var upstream = dnsmasq ? uci.get('dhcp', dnsmasq['.name'], 'server') : null;
		var noresolv = dnsmasq ? uci.get('dhcp', dnsmasq['.name'], 'noresolv') : null;

		var expected = [ 'NTP server', 'is not reachable', 'stream truncated',
			'unknown key' ];

		var errors = splitRuns(log).pop().split('\n').filter(function (line) {
			return line.indexOf('[error]') >= 0 &&
				!expected.some(function (text) {
					return line.indexOf(text) >= 0;
				});
		});

		var mtu = linkLine.match(/mtu (\d+)/);

		var pinged = r[7] && r[7].code === 0;
		var stats = r[8] || {};
		var bypass = routes.split('\n').filter(function (line) {
			return line.indexOf('via ') >= 0 && line.indexOf('dev ' + tun) < 0;
		}).length;

		return [
			{
				ok: uci.get('fptn', 'config', 'access_token') ? true : false,
				title: 'Access token is set',
				detail: uci.get('fptn', 'config', 'access_token')
					? 'configured' : 'empty, the client refuses to start'
			},
			{
				ok: uci.get('fptn', 'config', 'enabled') === '1',
				title: 'Client is enabled',
				detail: uci.get('fptn', 'config', 'enabled') === '1'
					? 'enabled' : 'disabled in configuration'
			},
			{
				ok: r[0],
				title: 'VPN process is running',
				detail: r[0] ? 'running' : 'stopped'
			},
			{
				ok: linkLine.indexOf(',UP') >= 0,
				title: 'Tunnel \'' + tun + '\' is up',
				detail: linkLine
					? 'up, MTU ' + (mtu ? mtu[1] : 'unknown')
					: 'interface does not exist'
			},
			{
				ok: addrLine !== '',
				title: 'Tunnel has an IPv4 address',
				detail: addrLine
					? (addrLine.match(/inet ([0-9./]+)/) || [ '', 'unknown' ])[1]
					: 'no address assigned'
			},
			{
				ok: defaultLine.indexOf('dev ' + tun) >= 0,
				title: 'Default route goes through the tunnel',
				detail: defaultLine || 'no default route at all'
			},
			{
				ok: zones.length > 0,
				title: 'Firewall zone \'fptn\' exists',
				detail: zones.length
					? 'present, LAN clients are masqueraded'
					: 'missing, LAN clients will not reach the internet'
			},
			{
				ok: uci.get('fptn', 'config', 'use_fptn_dns') !== '1' ||
					(noresolv === '1' && upstream != null),
				title: 'dnsmasq forwards DNS into the tunnel',
				detail: uci.get('fptn', 'config', 'use_fptn_dns') !== '1'
					? 'turned off in settings, router DNS is left untouched'
					: (upstream
						? 'upstream ' + [].concat(upstream).join(', ') +
							(noresolv === '1' ? '' : ', but noresolv is off')
						: 'not configured, DNS queries bypass the VPN')
			},
			{
				ok: pinged,
				title: 'The internet answers through the tunnel',
				detail: pinged
					? '8.8.8.8 replies'
					: '8.8.8.8 does not reply, traffic does not pass the tunnel'
			},
			{
				ok: parseInt(stats.rx, 10) > 0,
				title: 'The tunnel carries traffic in both directions',
				detail: 'sent ' + formatBytes(stats.tx) +
					', received ' + formatBytes(stats.rx)
			},
			{
				ok: bypass < 100,
				title: 'Split tunneling keeps a sane number of bypass routes',
				detail: bypass + ' addresses go around the tunnel' +
					(bypass < 100 ? '' : ', too many, check the domain lists')
			},
			{
				ok: errors.length === 0,
				title: 'No unexpected errors since the client started',
				detail: errors.length
					? errors.length + ' error line(s), see the Log section'
					: 'clean, apart from the usual server probe failures'
			}
		];
	});
}

function showDiagnostics() {
	return diagnose().then(function (checks) {
		var failed = checks.filter(function (check) {
			return !check.ok;
		});

		var rows = checks.map(function (check) {
			return E('div', { 'style': 'padding:.4em 0;border-top:1px solid rgba(128,128,128,.3)' }, [
				E('span', {
					'style': 'font-weight:bold;color:' + (check.ok ? '#00a000' : '#a00000')
				}, (check.ok ? '✓ ' : '✗ ') + check.title),
				E('div', { 'style': 'opacity:.7;padding-left:1.4em' }, check.detail)
			]);
		});

		var pending = ui.changes.numChanges > 0
			? E('div', { 'style': 'padding:.5em;color:#a08000' },
				'There are unsaved changes. The checks below look at the applied ' +
				'configuration — press "Save & Apply" first.')
			: '';

		ui.showModal('Diagnostics', [
			E('div', {
				'style': 'padding:.5em;font-weight:bold;color:' +
					(failed.length ? '#a00000' : '#00a000')
			}, failed.length
				? failed.length + ' check(s) failed'
				: 'Everything looks fine'),
			pending,
			E('div', {}, rows),
			E('div', { 'class': 'right' }, E('button', {
				'class': 'cbi-button',
				'click': ui.hideModal
			}, 'Close'))
		]);
	});
}

function reconcile(running) {
	var enabled = uci.get('fptn', 'config', 'enabled') === '1';

	if (enabled === running)
		return Promise.resolve();

	return fs.exec('/etc/init.d/fptn', [ enabled ? 'restart' : 'stop' ])
		.catch(function (err) {
			ui.addNotification(null, E('p', 'fptn: ' + err), 'error');
		});
}

function splitRuns(log) {
	var runs = [], current = '';

	log.split('\n').forEach(function (line) {
		if (line.indexOf('Application started successfully') >= 0) {
			runs.push(current);
			current = '';
		}
		current += line + '\n';
	});
	runs.push(current);

	return runs;
}

function failedRuns(log, needles) {
	var runs = splitRuns(log), streak = 0;

	for (var i = runs.length - 1; i >= 0; i--) {
		var run = runs[i];
		var failed = needles.some(function (needle) {
			return run.indexOf(needle) >= 0;
		});

		if (failed)
			streak++;
		else if (run.indexOf('Starting client') >= 0)
			break;
	}

	return streak;
}

function lastRunHas(log, needles) {
	var runs = splitRuns(log);
	var run = runs[runs.length - 1];

	return needles.some(function (needle) {
		return run.indexOf(needle) >= 0;
	});
}

function problemNote(log, connected) {
	if (!uci.get('fptn', 'config', 'access_token'))
		return 'no token configured';

	if (connected)
		return '';

	if (lastRunHas(log, [ 'no default route', 'default gateway not found',
			'Unable to find the default gateway' ]))
		return 'the router has no default route — check the WAN connection';

	if (failedRuns(log, [ 'Config error' ]) >= 3)
		return 'this access token cannot be read — copy it again from ' + botLink;

	if (failedRuns(log, [ 'Status: 401', 'Login failed (code 401)' ]) >= 3)
		return 'the servers reject this access token — it has expired or is ' +
			'invalid, get a fresh one from ' + botLink;

	if (failedRuns(log, [ 'DNS resolve error', 'DNS server error' ]) >= 3)
		return 'the router cannot resolve server names — check its own DNS ' +
			'settings under Network → DNS';

	if (failedRuns(log, [ 'does not exist! Check your token' ]) >= 3)
		return 'the server named in "Preferred server" is not in this token — ' +
			'clear the field or choose another one';

	if (failedRuns(log, [ 'All servers unavailable' ]) >= 5)
		return 'no server could be reached — try another bypass blocking ' +
			'method, or get a fresh token from ' + botLink;

	return '';
}

function describe(running, tunnel) {
	if (!running)
		return [ 'Stopped', '#a00000' ];
	if (!tunnel)
		return [ 'Connecting…', '#a08000' ];

	return [ 'Connected', '#00a000' ];
}

function collect() {
	var tun = uci.get('fptn', 'config', 'tun_interface_name') || 'tun0';

	return Promise.all([
		serviceInfo(), hasTunnel(), readLog(), tunnelStats(tun)
	]);
}

function statusRows(data) {
	var state = describe(data[0].running, data[1]);
	var stats = data[3] || {};
	var log = data[2] || '';

	var lastEvent = log.split('\n').filter(function (line) {
		return line.trim() !== '';
	}).pop() || '';

	return [
		[ 'Connection', state[0], state[1] ],
		[ 'Autostart on boot',
			uci.get('fptn', 'config', 'enabled') === '1' ? 'on' : 'off' ],
		[ 'Selected server',
			uci.get('fptn', 'config', 'preferred_server') || 'Auto' ],
		[ 'Bypass blocking method',
			uci.get('fptn', 'config', 'bypass_method') || 'obfuscation' ],
		[ 'Split tunneling',
			uci.get('fptn', 'config', 'enable_split_tunnel') === '1'
				? uci.get('fptn', 'config', 'split_tunnel_mode') || 'exclude'
				: 'off' ],
		[ 'Tunnel interface',
			uci.get('fptn', 'config', 'tun_interface_name') || 'tun0' ],
		[ 'PID', data[0].pid ? String(data[0].pid) : '—' ],
		[ 'Received', formatBytes(stats.rx) ],
		[ 'Sent', formatBytes(stats.tx) ],
		[ 'Client restarts', restarts(log) ],
		[ 'Last event', lastEvent.replace(/^.*?\]\s*/, '') || '—' ]
	];
}

function refresh() {
	return collect().then(function (data) {
		var rows = statusRows(data);

		var status = document.getElementById('fptn_status');
		if (status) {
			status.textContent = rows[0][1];
			status.style.color = rows[0][2];
		}

		var note = document.getElementById('fptn_note');
		if (note)
			note.innerHTML = ' ' + problemNote(data[2] || '', data[1]);

		rows.forEach(function (row, index) {
			var node = document.getElementById('fptn_st' + index);
			if (!node)
				return;

			node.textContent = row[1];
			if (row[2])
				node.style.color = row[2];
		});

		var log = document.getElementById('fptn_log');
		if (log)
			log.textContent = logTail(data[2] || '') || 'No messages yet';

		return data;
	});
}

return view.extend({
	handleSaveApply: function (ev, mode) {
		return this.super('handleSaveApply', [ ev, mode ]).then(function () {
			return fs.exec('/etc/init.d/fptn', [ 'restart' ]).then(refresh);
		});
	},

	load: function () {
		return uci.load('fptn').then(function () {
			var tun = uci.get('fptn', 'config', 'tun_interface_name') || 'tun0';

			return Promise.all([
				serviceInfo(), hasTunnel(), readLog(), tunnelStats(tun)
			]);
		});
	},

	render: function (data) {
		var m, s, o;
		var running = data[0].running;
		var state = describe(running, data[1]);
		var token = uci.get('fptn', 'config', 'access_token');

		reconcile(running);
		poll.add(refresh, 5);

		m = new form.Map('fptn', 'FPTN VPN', 'Censorship-resistant VPN');

		s = m.section(form.NamedSection, 'config', 'fptn', 'Getting started');
		s.anonymous = true;

		o = s.option(form.DummyValue, '_help');
		o.rawhtml = true;
		o.cfgvalue = function () {
			return '<ol style="margin:0;padding-inline-start:1.5em">' +
				'<li>Open ' + botLink + ' in Telegram and copy the access token.</li>' +
				'<li>Paste it into the "Access token" field below and press "Save &amp; Apply".</li>' +
				'</ol>';
		};

		o = s.option(form.Flag, 'enabled', 'Enabled');
		o.rmempty = false;

		var enabledOption = o;

		o = s.option(form.DummyValue, '_status', 'Service');
		o.rawhtml = true;
		o.cfgvalue = function () {
			return '<span id="fptn_status" style="font-weight:bold;color:' +
				state[1] + '">' + state[0] + '</span>' +
				'<span id="fptn_note" style="color:#a00000"> ' +
				problemNote(data[2] || '', data[1]) + '</span>';
		};

		o = s.option(form.DummyValue, '_update', 'Version');
		o.renderWidget = function () {
			var node = E('span', {}, packageVersion);

			checkUpdate().then(function (latest) {
				if (!latest)
					return;

				node.appendChild(E('span', {}, [ ' — ', E('a', {
					'href': 'https://github.com/fptn-project/fptn/releases/latest',
					'target': '_blank',
					'rel': 'noreferrer'
				}, 'version ' + latest + ' is available') ]));
			});

			return node;
		};

		o = s.option(form.Button, '_diagnostics');
		o.inputtitle = 'Diagnostics';
		o.inputstyle = 'apply';
		o.onclick = function () {
			return showDiagnostics();
		};

		s = m.section(form.NamedSection, 'config', 'fptn');
		s.anonymous = true;
		s.tab('status', 'Status');
		s.tab('general', 'Settings');
		s.tab('routing', 'Routing');

		statusRows(data).forEach(function (row, index) {
			var field = s.taboption('status', form.DummyValue, '_st' + index, row[0]);
			field.rawhtml = true;
			field.cfgvalue = function () {
				return '<span id="fptn_st' + index + '"' +
					(row[2] ? ' style="font-weight:bold;color:' + row[2] + '"' : '') +
					'>' + row[1] + '</span>';
			};
		});

		o = s.taboption('general', form.TextValue, 'access_token', 'Access token',
			'Token issued by ' + botLink + ' in Telegram. It carries the server ' +
			'list, so get a new one when the current token expires.');
		o.rows = 4;
		o.rmempty = false;

		o = s.taboption('general', form.Value, 'preferred_server', 'Preferred server',
			'Name of the server to connect to, as listed by the Telegram bot. ' +
			'Leave empty and the client logs in to every server at once and ' +
			'keeps the one that answers first.');
		o.rmempty = true;

		o = s.taboption('general', form.ListValue, 'connection_strategy',
			'Connection strategy',
			'How many tunnels are kept open at the same time. Every tunnel is ' +
			'replaced by a new one each 10 minutes, and traffic is spread ' +
			'across them, so no single connection carries the whole session.');
		o.value('rolling-tunnel', 'Rolling tunnel');
		o.value('dual-rolling-tunnel', 'Dual rolling tunnel');
		o.value('triple-rolling-tunnel', 'Triple rolling tunnel');
		o.default = 'dual-rolling-tunnel';

		o = s.taboption('general', form.ListValue, 'bypass_method',
			'Bypass blocking method',
			'How the connection is disguised. Traffic masking hides it inside ' +
			'an ordinary TLS stream; the browser options copy the TLS handshake ' +
			'of that browser, so the connection looks like a visit to the ' +
			'domain set below.');
		o.value('obfuscation', 'Traffic masking (obfuscation)');
		spoofingMethods.forEach(function (method) {
			o.value(method[0], method[1]);
		});
		o.default = 'obfuscation';

		o = s.taboption('general', form.Value, 'mtu_size', 'Tunnel MTU',
			'Largest packet the tunnel carries. 1420 fits almost every ' +
			'provider; lower it if big packets get stuck while small ones ' +
			'pass. Allowed range is 576 to 65535.');
		o.datatype = 'range(576, 65535)';
		o.placeholder = '1420';
		o.rmempty = true;

		o = s.taboption('general', form.Value, 'sni', 'Fake domain to bypass blocking',
			'Domain name sent in the TLS handshake instead of the real server ' +
			'address. Empty means rutube.ru. Pick a popular site that is not ' +
			'blocked where you are.');
		spoofingMethods.forEach(function (method) {
			o.depends('bypass_method', method[0]);
		});
		o.rmempty = true;

		o = s.taboption('routing', form.Flag, 'use_fptn_dns', 'Use FPTN DNS',
			'Send DNS queries through the tunnel. When off, FPTN does not touch the router DNS settings at all.');
		o.default = '1';
		o.rmempty = false;

		o = s.taboption('routing', form.Flag, 'enable_split_tunnel',
			'Enable split tunneling',
			'When enabled, you can configure which sites use VPN and which go directly.');
		o.default = '1';
		o.rmempty = false;

		o = s.taboption('routing', form.ListValue, 'split_tunnel_mode',
			'Split tunnel mode',
			'Defines traffic routing strategy for split tunneling.');
		o.value('exclude', 'Exclude');
		o.value('include', 'Include');
		o.default = 'exclude';
		o.depends('enable_split_tunnel', '1');

		o = listOption(s, 'routing', 'split_tunnel_domains_exclude',
			'split_tunnel_domains', 'Domains to bypass VPN',
			'List domains that should bypass VPN tunnel. These domains will go directly, all other traffic uses VPN',
			'example.com');
		o.depends({ enable_split_tunnel: '1', split_tunnel_mode: 'exclude' });

		o = listOption(s, 'routing', 'split_tunnel_domains_include',
			'split_tunnel_domains', 'Domains to route through VPN',
			'List domains that should use VPN tunnel. Only these domains will go through VPN, all other traffic bypasses VPN',
			'example.com');
		o.depends({ enable_split_tunnel: '1', split_tunnel_mode: 'include' });

		listOption(s, 'routing', 'blacklist_domains', 'blacklist_domains',
			'Blacklist domains',
			'Completely block access to the main domain AND all its subdomains. Format: example.com (one per line)',
			'example.com');

		listOption(s, 'routing', 'exclude_tunnel_networks', 'exclude_tunnel_networks',
			'Exclude tunnel networks',
			'Networks that always bypass VPN tunnel. Traffic to these networks goes directly, never through VPN',
			'10.0.0.0/8');

		listOption(s, 'routing', 'include_tunnel_networks', 'include_tunnel_networks',
			'Include tunnel networks',
			'Networks that always use VPN tunnel. Traffic to these networks always goes through VPN',
			'192.168.99.0/24');

		s = m.section(form.NamedSection, 'config', 'fptn', 'Log');
		s.anonymous = true;

		o = s.option(form.DummyValue, '_log');
		o.rawhtml = true;
		o.cfgvalue = function () {
			var text = logTail(data[2] || '') || 'No messages yet';
			return '<pre id="fptn_log" style="max-height:20em;overflow:auto">' +
				text.replace(/[&<>]/g, function (c) {
					return { '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c];
				}) + '</pre>';
		};

		return m.render().then(function (node) {
			var sections = node.querySelectorAll('.cbi-section');

			var toggle = function () {
				var on = enabledOption.formvalue('config') === '1';

				for (var i = 1; i < sections.length; i++)
					sections[i].hidden = !on;
			};

			node.addEventListener('change', toggle);
			toggle();

			return node;
		});
	}
});
