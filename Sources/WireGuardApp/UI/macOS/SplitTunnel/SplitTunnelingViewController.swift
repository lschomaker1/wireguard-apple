// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Cocoa
import UniformTypeIdentifiers

class SplitTunnelingViewController: NSViewController {

    private struct AppListItem {
        let app: SplitTunnelApp
        var isExcluded: Bool
        var isRunning: Bool
    }

    private var items = [AppListItem]()

    private let headerLabel: NSTextField = {
        let label = NSTextField(labelWithString: tr("macSplitTunnelingHeader"))
        label.font = NSFont.boldSystemFont(ofSize: NSFont.systemFontSize)
        return label
    }()

    private let infoLabel: NSTextField = {
        let label = NSTextField(wrappingLabelWithString: tr("macSplitTunnelingInfo"))
        label.font = NSFont.systemFont(ofSize: NSFont.smallSystemFontSize)
        label.textColor = .secondaryLabelColor
        return label
    }()

    private let tableView: NSTableView = {
        let tableView = NSTableView()
        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("app"))
        column.width = 400
        tableView.addTableColumn(column)
        tableView.headerView = nil
        tableView.rowHeight = 40
        tableView.usesAlternatingRowBackgroundColors = true
        tableView.allowsMultipleSelection = false
        return tableView
    }()

    private let scrollView: NSScrollView = {
        let scrollView = NSScrollView()
        scrollView.hasVerticalScroller = true
        scrollView.autohidesScrollers = true
        scrollView.borderType = .bezelBorder
        return scrollView
    }()

    private let addAppButton: NSButton = {
        let button = NSButton(title: tr("macSplitTunnelingAddApp"), target: nil, action: #selector(SplitTunnelingViewController.addApplicationClicked))
        return button
    }()

    private let statusLabel: NSTextField = {
        let label = NSTextField(wrappingLabelWithString: "")
        label.font = NSFont.systemFont(ofSize: NSFont.smallSystemFontSize)
        label.textColor = .secondaryLabelColor
        return label
    }()

    override func loadView() {
        tableView.dataSource = self
        tableView.delegate = self
        tableView.columnAutoresizingStyle = .lastColumnOnlyAutoresizingStyle

        scrollView.documentView = tableView

        addAppButton.target = self

        let containerView = NSView()
        [headerLabel, infoLabel, scrollView, addAppButton, statusLabel].forEach { subview in
            subview.translatesAutoresizingMaskIntoConstraints = false
            containerView.addSubview(subview)
        }

        NSLayoutConstraint.activate([
            headerLabel.topAnchor.constraint(equalTo: containerView.topAnchor, constant: 20),
            headerLabel.leadingAnchor.constraint(equalTo: containerView.leadingAnchor, constant: 20),
            headerLabel.trailingAnchor.constraint(lessThanOrEqualTo: containerView.trailingAnchor, constant: -20),

            infoLabel.topAnchor.constraint(equalTo: headerLabel.bottomAnchor, constant: 6),
            infoLabel.leadingAnchor.constraint(equalTo: containerView.leadingAnchor, constant: 20),
            infoLabel.trailingAnchor.constraint(equalTo: containerView.trailingAnchor, constant: -20),

            scrollView.topAnchor.constraint(equalTo: infoLabel.bottomAnchor, constant: 12),
            scrollView.leadingAnchor.constraint(equalTo: containerView.leadingAnchor, constant: 20),
            scrollView.trailingAnchor.constraint(equalTo: containerView.trailingAnchor, constant: -20),

            addAppButton.topAnchor.constraint(equalTo: scrollView.bottomAnchor, constant: 12),
            addAppButton.leadingAnchor.constraint(equalTo: containerView.leadingAnchor, constant: 20),
            addAppButton.bottomAnchor.constraint(equalTo: containerView.bottomAnchor, constant: -20),

            statusLabel.centerYAnchor.constraint(equalTo: addAppButton.centerYAnchor),
            statusLabel.leadingAnchor.constraint(equalTo: addAppButton.trailingAnchor, constant: 12),
            statusLabel.trailingAnchor.constraint(equalTo: containerView.trailingAnchor, constant: -20),

            containerView.widthAnchor.constraint(greaterThanOrEqualToConstant: 480),
            scrollView.heightAnchor.constraint(greaterThanOrEqualToConstant: 320)
        ])

        view = containerView
    }

    override func viewDidLoad() {
        super.viewDidLoad()

        let workspaceNotificationCenter = NSWorkspace.shared.notificationCenter
        workspaceNotificationCenter.addObserver(self, selector: #selector(runningApplicationsChanged), name: NSWorkspace.didLaunchApplicationNotification, object: nil)
        workspaceNotificationCenter.addObserver(self, selector: #selector(runningApplicationsChanged), name: NSWorkspace.didTerminateApplicationNotification, object: nil)
        NotificationCenter.default.addObserver(self, selector: #selector(splitTunnelStateChanged), name: .splitTunnelStateDidChange, object: nil)

        reloadItems()
    }

    deinit {
        NSWorkspace.shared.notificationCenter.removeObserver(self)
        NotificationCenter.default.removeObserver(self)
    }

    override func viewWillAppear() {
        super.viewWillAppear()
        reloadItems()
    }

    @objc private func runningApplicationsChanged() {
        reloadItems()
    }

    @objc private func splitTunnelStateChanged() {
        updateStatusLabel()
    }

    private func reloadItems() {
        // Backfill code-signing teams for apps saved before team matching existed,
        // so existing selections gain whole-vendor coverage without re-adding.
        var excludedApps = SplitTunnelManager.shared.excludedApps
        var didBackfill = false
        for index in excludedApps.indices where (excludedApps[index].teamIdentifier ?? "").isEmpty {
            if let team = CodeSigning.teamIdentifier(forBundleAt: excludedApps[index].bundlePath) {
                excludedApps[index].teamIdentifier = team
                didBackfill = true
            }
        }
        if didBackfill {
            SplitTunnelManager.shared.setExcludedApps(excludedApps)
        }

        var itemsByKey = [String: AppListItem]()
        for app in excludedApps {
            let key = app.bundleIdentifier.isEmpty ? app.bundlePath : app.bundleIdentifier
            itemsByKey[key] = AppListItem(app: app, isExcluded: true, isRunning: false)
        }

        let ownBundleIdentifier = Bundle.main.bundleIdentifier
        for runningApp in NSWorkspace.shared.runningApplications {
            guard runningApp.activationPolicy == .regular else { continue }
            guard let bundleIdentifier = runningApp.bundleIdentifier, bundleIdentifier != ownBundleIdentifier else { continue }
            if var existingItem = itemsByKey[bundleIdentifier] {
                existingItem.isRunning = true
                itemsByKey[bundleIdentifier] = existingItem
            } else {
                let bundlePath = runningApp.bundleURL?.path ?? ""
                let app = SplitTunnelApp(bundleIdentifier: bundleIdentifier,
                                         name: runningApp.localizedName ?? bundleIdentifier,
                                         bundlePath: bundlePath,
                                         teamIdentifier: CodeSigning.teamIdentifier(forBundleAt: bundlePath))
                itemsByKey[bundleIdentifier] = AppListItem(app: app, isExcluded: false, isRunning: true)
            }
        }

        items = itemsByKey.values.sorted { $0.app.name.localizedCaseInsensitiveCompare($1.app.name) == .orderedAscending }
        tableView.reloadData()
        updateStatusLabel()
    }

    private func updateStatusLabel() {
        let excludedCount = items.filter { $0.isExcluded }.count
        if excludedCount == 0 {
            statusLabel.stringValue = tr("macSplitTunnelingStatusNoApps")
        } else if SplitTunnelManager.shared.isAnyTunnelActive {
            statusLabel.stringValue = tr(format: "macSplitTunnelingStatusActive (%d)", excludedCount)
        } else {
            statusLabel.stringValue = tr("macSplitTunnelingStatusInactive")
        }
    }

    private func applyExclusions() {
        let excludedApps = items.filter { $0.isExcluded }.map { $0.app }
        SplitTunnelManager.shared.setExcludedApps(excludedApps)
        updateStatusLabel()
    }

    @objc private func checkboxToggled(_ sender: NSButton) {
        let row = tableView.row(for: sender)
        guard row >= 0 && row < items.count else { return }
        items[row].isExcluded = sender.state == .on
        applyExclusions()
    }

    @objc private func addApplicationClicked() {
        guard let window = view.window else { return }
        let panel = NSOpenPanel()
        panel.directoryURL = URL(fileURLWithPath: "/Applications")
        panel.allowedContentTypes = [.applicationBundle]
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        panel.beginSheetModal(for: window) { [weak self] response in
            guard let self = self, response == .OK else { return }
            var excludedApps = SplitTunnelManager.shared.excludedApps
            for url in panel.urls {
                guard let bundle = Bundle(url: url) else { continue }
                let name = (bundle.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String)
                    ?? (bundle.object(forInfoDictionaryKey: "CFBundleName") as? String)
                    ?? url.deletingPathExtension().lastPathComponent
                let app = SplitTunnelApp(bundleIdentifier: bundle.bundleIdentifier ?? "",
                                         name: name,
                                         bundlePath: url.path,
                                         teamIdentifier: CodeSigning.teamIdentifier(forBundleAt: url.path))
                let isAlreadyExcluded = excludedApps.contains { existing in
                    if !existing.bundleIdentifier.isEmpty && !app.bundleIdentifier.isEmpty {
                        return existing.bundleIdentifier == app.bundleIdentifier
                    }
                    return existing.bundlePath == app.bundlePath
                }
                if !isAlreadyExcluded {
                    excludedApps.append(app)
                }
            }
            SplitTunnelManager.shared.setExcludedApps(excludedApps)
            self.reloadItems()
        }
    }
}

extension SplitTunnelingViewController: NSTableViewDataSource, NSTableViewDelegate {
    func numberOfRows(in tableView: NSTableView) -> Int {
        return items.count
    }

    func tableView(_ tableView: NSTableView, viewFor tableColumn: NSTableColumn?, row: Int) -> NSView? {
        let item = items[row]

        let cellView = NSView()

        let checkbox = NSButton(checkboxWithTitle: "", target: self, action: #selector(checkboxToggled(_:)))
        checkbox.state = item.isExcluded ? .on : .off

        let iconView = NSImageView()
        iconView.image = item.app.bundlePath.isEmpty ? nil : NSWorkspace.shared.icon(forFile: item.app.bundlePath)
        iconView.imageScaling = .scaleProportionallyUpOrDown

        let nameLabel = NSTextField(labelWithString: item.app.name)
        nameLabel.font = NSFont.systemFont(ofSize: NSFont.systemFontSize)
        nameLabel.lineBreakMode = .byTruncatingTail

        let detailText = item.isRunning ? item.app.bundleIdentifier : tr("macSplitTunnelingAppNotRunning")
        let detailLabel = NSTextField(labelWithString: detailText)
        detailLabel.font = NSFont.systemFont(ofSize: NSFont.smallSystemFontSize)
        detailLabel.textColor = .secondaryLabelColor
        detailLabel.lineBreakMode = .byTruncatingTail

        [checkbox, iconView, nameLabel, detailLabel].forEach { subview in
            subview.translatesAutoresizingMaskIntoConstraints = false
            cellView.addSubview(subview)
        }

        NSLayoutConstraint.activate([
            checkbox.leadingAnchor.constraint(equalTo: cellView.leadingAnchor, constant: 8),
            checkbox.centerYAnchor.constraint(equalTo: cellView.centerYAnchor),

            iconView.leadingAnchor.constraint(equalTo: checkbox.trailingAnchor, constant: 8),
            iconView.centerYAnchor.constraint(equalTo: cellView.centerYAnchor),
            iconView.widthAnchor.constraint(equalToConstant: 32),
            iconView.heightAnchor.constraint(equalToConstant: 32),

            nameLabel.leadingAnchor.constraint(equalTo: iconView.trailingAnchor, constant: 8),
            nameLabel.trailingAnchor.constraint(lessThanOrEqualTo: cellView.trailingAnchor, constant: -8),
            nameLabel.topAnchor.constraint(equalTo: cellView.topAnchor, constant: 4),

            detailLabel.leadingAnchor.constraint(equalTo: nameLabel.leadingAnchor),
            detailLabel.trailingAnchor.constraint(lessThanOrEqualTo: cellView.trailingAnchor, constant: -8),
            detailLabel.topAnchor.constraint(equalTo: nameLabel.bottomAnchor, constant: 1)
        ])

        return cellView
    }

    func tableView(_ tableView: NSTableView, shouldSelectRow row: Int) -> Bool {
        return false
    }
}
