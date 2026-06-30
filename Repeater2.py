# -*- coding: utf-8 -*-
"""
Repeater2 - Combined Burp Suite extension
Jython 2.7 / Legacy Extender API

Merges three independent extensions into a single installable extension,
each living on its own sub-tab inside one "Repeater2" suite tab:
  1. NoAuth        - strips auth material from Repeater requests and queues
                      the stripped copy for replay (auth-bypass testing)
  2. JWT Attacker   - detects JWTs in Repeater requests and queues
                      unverified-signature / alg:none attack variants
  3. AuthzTester    - captures Repeater requests into named user profiles
                      and injects low-privilege auth material before
                      bulk-sending (IDOR / BFLA / BOLA testing)
"""

from burp import (
    IBurpExtender, ITab, IHttpListener, IMessageEditorController,
    IContextMenuFactory
)

from javax.swing import (
    JPanel, JTable, JButton, JScrollPane, JSplitPane, JTabbedPane,
    ListSelectionModel, BorderFactory, JLabel, SwingConstants,
    JComboBox, JTextField, JTextArea, JCheckBox, JMenuItem,
    JOptionPane, JFileChooser, JPopupMenu, AbstractAction, DefaultCellEditor,
    SwingUtilities
)
from javax.swing.table import AbstractTableModel, DefaultTableCellRenderer, TableRowSorter
from javax.swing import RowFilter
from javax.swing.event import ListSelectionListener
from javax.swing.border import TitledBorder
from java.awt import (BorderLayout, FlowLayout, Dimension, Color, Font, Insets,
                       GradientPaint, RenderingHints, Cursor, GridLayout, Toolkit)
from java.awt.event import ActionListener, MouseAdapter
from java.lang import System as JavaSystem
from java.lang import Object as JavaObject
from java.lang import Integer, String
from java.lang import Runnable, System
from java.util import Comparator, ArrayList
from array import array
from collections import OrderedDict
import threading
import time
import hashlib
import os
import re
import json
import base64
import java.io
try:
    from urllib import unquote  # Jython / Python 2
except ImportError:
    from urllib.parse import unquote  # Python 3 fallback


# ---------------------------------------------------------------------------
# DPI-aware UI scaling  (independent of OS, Burp zoom, system font size)
# ---------------------------------------------------------------------------
# Read the physical screen DPI once at import time.  96 dpi = scale 1.0,
# 144 dpi (150 % HiDPI) = 1.5, 192 dpi (200 %) = 2.0, etc.
# All pixel/point values in this file derive from _S() / _I() so the whole
# UI stays proportional on every screen without touching Burp's own settings.

def _ui_scale():
    try:
        dpi = Toolkit.getDefaultToolkit().getScreenResolution()
        return max(1.0, dpi / 96.0)
    except Exception:
        return 1.0

# _SCALE_BOX holds the live scale factor in a list so all helpers always
# read the current value even after the user changes it at runtime.
_SCALE_BOX = [_ui_scale()]

def _SCALE():
    return _SCALE_BOX[0]

def set_scale(factor):
    """Change the global UI scale factor (called by the ScaleBar combo)."""
    _SCALE_BOX[0] = float(factor)

def _S(px):
    """Scale an integer pixel/point value by the current UI scale factor."""
    return int(round(px * _SCALE()))

def _F(pt):
    """Return a float font-point size scaled to the current UI scale factor."""
    return float(pt * _SCALE())

def _I(top, right=None, bottom=None, left=None):
    """Return scaled Insets.  Call as _I(v,h) or _I(t,r,b,l)."""
    if right is None:
        v = _S(top); return Insets(v, v, v, v)
    if bottom is None:
        v = _S(top); h = _S(right); return Insets(v, h, v, h)
    return Insets(_S(top), _S(right), _S(bottom), _S(left))

def _D(w, h):
    """Return a scaled Dimension."""
    return Dimension(_S(w), _S(h))

# Available scale presets shown in the UI dropdown
SCALE_PRESETS = [("75%", 0.75), ("100%", 1.0), ("125%", 1.25),
                 ("150%", 1.5), ("175%", 1.75), ("200%", 2.0)]

# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

EMPTY_BYTES = array('b', [])

# Catches a JWT (header.payload.signature) anywhere in text.
JWT_REGEX = re.compile(r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*')

# Looser fallback - doesn't require the literal "eyJ" prefix and also
# tolerates URL-encoded dots (%2E). Used as a fallback when re-locating a
# JWT inside an already-mutated queued request (e.g. an alg:none variant
# whose header no longer starts with "eyJ", or a token sitting in a
# URL-encoded parameter) since the strict JWT_REGEX above can miss those.
LOOSE_JWT_REGEX = re.compile(r'[A-Za-z0-9_\-]{8,}(?:\.|%2E|%2e)[A-Za-z0-9_\-]+(?:\.|%2E|%2e)[A-Za-z0-9_\-]*')


try:
    STRING_TYPES = (str, unicode)
except NameError:
    STRING_TYPES = (str,)

# ---- shared dark theme ----
BG_PANEL = Color(35, 38, 41)
BG_HEADER = Color(24, 26, 28)
ROW_EVEN = Color(43, 47, 51)
ROW_ODD = Color(52, 56, 61)
ROW_SELECTED = Color(95, 95, 237)  # #5f5fed - purple/blue selection tab
TEXT_LIGHT = Color(225, 228, 230)
TEXT_MUTED = Color(170, 174, 178)

GREEN = Color(46, 204, 113)
ORANGE = Color(243, 156, 18)
RED = Color(231, 76, 60)
DARK_RED = Color(178, 34, 34)
BLUE_GRAY = Color(90, 130, 180)
QUEUED_COLOR = Color(64, 196, 200)
CLEAR_SELECTED_COLOR = Color(192, 57, 43)
INJECT_TOKEN_COLOR = Color(155, 89, 182)

# Distinct dark, recognizable text color for original/previous capture stats
PREV_COL_COLOR = Color(255, 60, 60) # Permanent bright red


class SharedNumericComparator(Comparator):
    def compare(self, a, b):
        try:
            ai = int(str(a))
        except (TypeError, ValueError):
            ai = -1
        try:
            bi = int(str(b))
        except (TypeError, ValueError):
            bi = -1
        if ai < bi:
            return -1
        if ai > bi:
            return 1
        return 0


class SharedFlashyNameLabel(JPanel):
    def __init__(self, text):
        JPanel.__init__(self)
        self.text = text
        self.setOpaque(False)
        self.font = Font("SansSerif", Font.BOLD | Font.ITALIC, _S(20))
        width = max(_S(220), len(text) * _S(11))
        self.setPreferredSize(Dimension(width, _S(32)))

    def paintComponent(self, g):
        g2 = g.create()
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON)
        g2.setFont(self.font)
        fm = g2.getFontMetrics()
        textWidth = fm.stringWidth(self.text)
        x = self.getWidth() - textWidth - 6
        y = (self.getHeight() + fm.getAscent()) // 2 - 2

        g2.setColor(Color(0, 0, 0, 170))
        g2.drawString(self.text, x + 2, y + 2)

        gradient = GradientPaint(x, 0, GREEN, x + textWidth, 0, RED)
        g2.setPaint(gradient)
        g2.drawString(self.text, x, y)
        g2.dispose()

# ===========================================================================
# Sub-extension 1: NoAuth
# ===========================================================================

AUTH_HEADERS = set([
    "authorization", "cookie", "proxy-authorization", "x-api-key",
    "x-auth-token", "x-access-token", "x-csrf-token", "token",
    "api-key", "x-amz-security-token"
])

AUTH_PARAM_NAMES = set([
    "token", "access_token", "accesstoken", "refresh_token", "refreshtoken",
    "id_token", "idtoken", "auth_token", "authtoken", "api_key", "apikey",
    "session", "sessionid", "session_id", "sid", "jwt", "csrf_token",
    "csrftoken", "xsrf_token", "secret", "client_secret", "password",
    "passwd", "pwd", "bearer", "authorization", "auth",
])


class NA_QueueItem(object):
    def __init__(self, httpService, requestBytes):
        self.httpService = httpService
        self.request = requestBytes
        self.response = None
        self.prev_status = ""
        self.prev_size = ""
        self.status = "queued"
        self.method = ""
        self.url = ""
        self.time_ms = ""
        self.size = ""
        self.history = []       
        self.historyIndex = -1  
        self.req_hash = None    


class NA_Profile(object):
    def __init__(self, name):
        self.name = name
        self.items = []            
        self.seen_requests = set()
        self.paused_rows = []


class NA_QueueTableModel(AbstractTableModel):
    columns = ["#", "Method", "URL", "Prev Status", "Status", "Prev Size", "Size (bytes)", "Time (ms)"]

    def __init__(self):
        self.items = []
        self._count_cb = None

    def getRowCount(self):
        return len(self.items)

    def getColumnCount(self):
        return len(self.columns)

    def getColumnName(self, col):
        return self.columns[col]

    def getValueAt(self, row, col):
        item = self.items[row]
        if col == 0: return row + 1
        if col == 1: return item.method
        if col == 2: return item.url
        if col == 3: return item.prev_status
        if col == 4: return item.status
        if col == 5: return item.prev_size
        if col == 6: return item.size
        if col == 7: return item.time_ms
        return ""

    def addItem(self, item):
        self.items.append(item)
        row = len(self.items) - 1
        self.fireTableRowsInserted(row, row)
        if self._count_cb: self._count_cb()

    def clear(self):
        del self.items[:]
        self.fireTableDataChanged()
        if self._count_cb: self._count_cb()

    def removeRows(self, rows):
        for row in sorted(set(rows), reverse=True):
            if 0 <= row < len(self.items):
                del self.items[row]
        self.fireTableDataChanged()
        if self._count_cb: self._count_cb()

    def getItem(self, row):
        return self.items[row]

    def fireRowUpdated(self, row):
        self.fireTableRowsUpdated(row, row)


class NA_StatusCellRenderer(DefaultTableCellRenderer):
    def __init__(self):
        DefaultTableCellRenderer.__init__(self)
        self.setHorizontalAlignment(SwingConstants.CENTER)

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col)
        comp.setBackground(ROW_SELECTED if isSelected else (ROW_EVEN if row % 2 == 0 else ROW_ODD))
        comp.setForeground(Color.WHITE)
        comp.setFont(comp.getFont().deriveFont(Font.BOLD))
        return comp


class NA_StripedCellRenderer(DefaultTableCellRenderer):
    def __init__(self):
        DefaultTableCellRenderer.__init__(self)
        self.setHorizontalAlignment(SwingConstants.CENTER)

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col)
        comp.setBackground(ROW_SELECTED if isSelected else (ROW_EVEN if row % 2 == 0 else ROW_ODD))
        
        # Keep it red even when selected
        if col == 3 or col == 5:  # Prev Status, Prev Size
            comp.setForeground(PREV_COL_COLOR)
        else:
            comp.setForeground(Color.WHITE)
            
        comp.setFont(comp.getFont().deriveFont(Font.BOLD))
        return comp


class NoAuthExtender(IMessageEditorController):
    def _init_state(self):
        """Initialise all data-bearing state. Safe to skip on UI rebuild."""
        self._profiles = {}
        self._profile_order = []
        self._active_profile_name = "Default"
        self._switching_profile = False
        default_profile = NA_Profile("Default")
        self._profiles["Default"] = default_profile
        self._profile_order.append("Default")

        self.tableModel = NA_QueueTableModel()
        self.tableModel._count_cb = lambda: self._count_cb() if self._count_cb else None
        self.tableModel.items = default_profile.items
        self.currentlyDisplayedItem = None
        self.enabled = True
        self.seen_requests = default_profile.seen_requests
        self._current_run_id = 0
        self._paused_rows = default_profile.paused_rows

        self.custom_strip_fields = set()
        self.custom_ignore_fields = set()
        self._count_cb = None   # set by BurpExtender after init

    def get_request_count(self):
        """Total requests across all profiles."""
        return sum(len(p.items) for p in self._profiles.values())

    def init(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._init_state()
        self._build_ui(callbacks)
        print("NoAuth (Repeater2 sub-tab) loaded.")

    def rebuild_ui(self):
        """Rebuild only the UI (after a scale change). State is preserved."""
        self._build_ui(self._callbacks)

    def _build_ui(self, callbacks):
        self.requestViewer = callbacks.createMessageEditor(self, True)
        self.responseViewer = callbacks.createMessageEditor(self, False)

        self.table = JTable(self.tableModel)
        self.table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self.table.getSelectionModel().addListSelectionListener(self._on_row_select)
        self.table.addMouseListener(QueueMouseAdapter(self))
        self.table.setRowHeight(_S(24))
        self.table.setShowGrid(False)
        self.table.setIntercellSpacing(Dimension(0, 0))
        self.table.setFillsViewportHeight(True)
        self.table.setBackground(ROW_EVEN)
        self.table.setForeground(TEXT_LIGHT)
        self.table.setSelectionBackground(ROW_SELECTED)
        self.table.setSelectionForeground(TEXT_LIGHT)
        self.table.setGridColor(BG_HEADER)

        header = self.table.getTableHeader()
        header.setFont(header.getFont().deriveFont(Font.BOLD))
        header.setBackground(BG_HEADER)
        header.setForeground(TEXT_LIGHT)
        header.setOpaque(True)
        headerRenderer = header.getDefaultRenderer()
        if isinstance(headerRenderer, DefaultTableCellRenderer):
            headerRenderer.setHorizontalAlignment(SwingConstants.CENTER)

        striped = NA_StripedCellRenderer()
        self.table.setDefaultRenderer(JavaObject, striped)
        statusCol = self.table.getColumnModel().getColumn(4)
        statusCol.setCellRenderer(NA_StatusCellRenderer())

        colModel = self.table.getColumnModel()
        colModel.getColumn(0).setPreferredWidth(35)   
        colModel.getColumn(1).setPreferredWidth(70)   
        colModel.getColumn(2).setPreferredWidth(300)  
        colModel.getColumn(3).setPreferredWidth(75)   
        colModel.getColumn(4).setPreferredWidth(70)   
        colModel.getColumn(5).setPreferredWidth(75)   
        colModel.getColumn(6).setPreferredWidth(85)   
        colModel.getColumn(7).setPreferredWidth(75)  

        self.rowSorter = TableRowSorter(self.tableModel)
        self.rowSorter.setComparator(5, SharedNumericComparator())  
        self.rowSorter.setComparator(6, SharedNumericComparator())  
        self.rowSorter.setComparator(7, SharedNumericComparator())  
        self.table.setRowSorter(self.rowSorter)

        tableScroll = JScrollPane(self.table)
        tableScroll.setPreferredSize(_D(900, 220))
        tableScroll.getViewport().setBackground(ROW_EVEN)
        tableScroll.setBackground(BG_PANEL)

        # ---- Search bar ----
        searchLabel = JLabel("Search:")
        searchLabel.setForeground(TEXT_MUTED)
        searchLabel.setFont(searchLabel.getFont().deriveFont(Font.BOLD, _F(8)))

        self._na_search_field = JTextField(22)
        self._na_search_field.setBackground(BG_HEADER)
        self._na_search_field.setForeground(TEXT_LIGHT)
        self._na_search_field.setCaretColor(TEXT_LIGHT)
        self._na_search_field.setToolTipText("Filter rows by URL, Method, or Status")
        self._na_search_field.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(BLUE_GRAY, 1),
            BorderFactory.createEmptyBorder(2, 6, 2, 6)
        ))

        _na_sorter = self.rowSorter
        _na_field  = self._na_search_field

        class _NASearchAction(ActionListener):
            def actionPerformed(self2, e):
                text = _na_field.getText().strip()
                if text:
                    try:
                        rf = RowFilter.regexFilter("(?i)" + re.escape(text))
                    except Exception:
                        rf = RowFilter.regexFilter("(?i)" + text)
                else:
                    rf = None
                _na_sorter.setRowFilter(rf)

        _na_action = _NASearchAction()

        from javax.swing.event import DocumentListener as _DocListener
        class _NADocListener(_DocListener):
            def insertUpdate(self2, e):  _na_action.actionPerformed(None)
            def removeUpdate(self2, e):  _na_action.actionPerformed(None)
            def changedUpdate(self2, e): _na_action.actionPerformed(None)

        _na_field.addActionListener(_na_action)
        _na_field.getDocument().addDocumentListener(_NADocListener())

        clearSearchBtn = JButton("x")
        clearSearchBtn.setOpaque(True)
        clearSearchBtn.setBorderPainted(False)
        clearSearchBtn.setFocusPainted(False)
        clearSearchBtn.setBackground(DARK_RED)
        clearSearchBtn.setForeground(Color.WHITE)
        clearSearchBtn.setFont(clearSearchBtn.getFont().deriveFont(Font.BOLD, _F(8)))
        clearSearchBtn.setMargin(_I(2, 6))
        clearSearchBtn.setToolTipText("Clear search")

        class _NAClearAction(ActionListener):
            def actionPerformed(self2, e):
                _na_field.setText("")
                _na_sorter.setRowFilter(None)

        clearSearchBtn.addActionListener(_NAClearAction())

        searchBar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        searchBar.setBackground(BG_PANEL)
        searchBar.add(searchLabel)
        searchBar.add(self._na_search_field)
        searchBar.add(clearSearchBtn)

        tablePanel = JPanel(BorderLayout())
        tablePanel.setBackground(BG_PANEL)
        tablePanel.setBorder(self._titled_border("Queued requests"))
        tablePanel.add(searchBar, BorderLayout.NORTH)
        tablePanel.add(tableScroll, BorderLayout.CENTER)
        # ---- end search bar ----

        prevBtn = self._make_nav_button("<")
        prevBtn.addActionListener(lambda e: self._nav_prev(e))
        nextBtn = self._make_nav_button(">")
        nextBtn.addActionListener(lambda e: self._nav_next(e))

        self.historyLabel = JLabel("No history", SwingConstants.CENTER)
        self.historyLabel.setForeground(TEXT_MUTED)
        self.historyLabel.setFont(self.historyLabel.getFont().deriveFont(Font.BOLD, _F(8)))

        navBar = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 4))
        navBar.setBackground(BG_PANEL)
        navBar.add(prevBtn)
        navBar.add(self.historyLabel)
        navBar.add(nextBtn)

        requestPanel = JPanel(BorderLayout())
        requestPanel.setBackground(BG_PANEL)
        requestPanel.add(navBar, BorderLayout.NORTH)
        requestPanel.add(self.requestViewer.getComponent(), BorderLayout.CENTER)

        editorSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                                  requestPanel,
                                  self.responseViewer.getComponent())
        editorSplit.setResizeWeight(0.5)
        editorSplit.setBackground(BG_PANEL)

        editorWrapper = JPanel(BorderLayout())
        editorWrapper.setBackground(BG_PANEL)
        editorWrapper.setBorder(self._titled_border("Request / Response"))
        editorWrapper.add(editorSplit, BorderLayout.CENTER)

        self.sendAllBtn = self._make_button("Send All", GREEN)
        self.sendAllBtn.addActionListener(lambda e: self._send_all(e))
        
        self.sendSelectedBtn = self._make_button("Send Selected", ORANGE)
        self.sendSelectedBtn.addActionListener(lambda e: self._send_selected(e))
        
        self.stopBtn = self._make_button("Stop", RED)
        self.stopBtn.setEnabled(False)
        self.stopBtn.addActionListener(lambda e: self._action_stop_sending(e))

        self.resumeBtn = self._make_button("Resume", QUEUED_COLOR)
        self.resumeBtn.setEnabled(False)
        self.resumeBtn.addActionListener(lambda e: self._resume_sending(e))

        clearSelectedBtn = self._make_button("Clear Selected", CLEAR_SELECTED_COLOR)
        clearSelectedBtn.addActionListener(lambda e: self._clear_selected(e))
        
        clearAllBtn = self._make_button("Clear All", DARK_RED)
        clearAllBtn.addActionListener(lambda e: self._clear_all(e))

        exportBtn = self._make_button("Export", BLUE_GRAY)
        exportBtn.addActionListener(lambda e: self._action_export_state())

        importBtn = self._make_button("Import", BLUE_GRAY)
        importBtn.addActionListener(lambda e: self._action_import_state())

        # --- Custom Strip Fields UI ---
        customFieldLabel = JLabel("Strip custom field:")
        customFieldLabel.setForeground(TEXT_MUTED)
        customFieldLabel.setFont(customFieldLabel.getFont().deriveFont(Font.BOLD, _F(8)))
        customFieldLabel.setToolTipText("Removes this field wherever it's found - header, body/query param, or JSON body key")

        self._customHeaderField = JTextField(9)
        self._customHeaderField.setToolTipText("Field name to strip (e.g. X-Faizan-Auth, user_id)")
        self._customHeaderField.setBackground(BG_HEADER)
        self._customHeaderField.setForeground(TEXT_LIGHT)
        self._customHeaderField.setCaretColor(TEXT_LIGHT)

        addCustomFieldBtn = self._make_button("+ Add", BLUE_GRAY)
        addCustomFieldBtn.setMargin(_I(4, 10))
        addCustomFieldBtn.addActionListener(lambda e: self._add_custom_strip_field())

        self._customFieldsDropdown = JComboBox()
        self._customFieldsDropdown.setToolTipText("Custom fields currently being stripped")
        self._customFieldsDropdown.setPreferredSize(Dimension(_S(130), self._customFieldsDropdown.getPreferredSize().height))

        deleteCustomFieldBtn = self._make_button("Delete", DARK_RED)
        deleteCustomFieldBtn.setMargin(_I(4, 10))
        deleteCustomFieldBtn.setToolTipText("Remove the custom field selected in the dropdown")
        deleteCustomFieldBtn.addActionListener(lambda e: self._remove_custom_strip_field())
        
        clearCustomFieldsBtn = self._make_button("Clear All", DARK_RED)
        clearCustomFieldsBtn.setMargin(_I(4, 10))
        clearCustomFieldsBtn.setToolTipText("Clear all custom strip fields from the dropdown")
        clearCustomFieldsBtn.addActionListener(lambda e: self._clear_all_custom_strip_fields())

        customFieldPanel = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
        customFieldPanel.setBackground(BG_PANEL)
        customFieldPanel.add(customFieldLabel)
        customFieldPanel.add(self._customHeaderField)
        customFieldPanel.add(addCustomFieldBtn)
        customFieldPanel.add(self._customFieldsDropdown)
        customFieldPanel.add(deleteCustomFieldBtn)
        customFieldPanel.add(clearCustomFieldsBtn)

        # --- Ignore/Exempt Fields UI ---
        ignoreFieldLabel = JLabel("Ignore field (Keep):")
        ignoreFieldLabel.setForeground(TEXT_MUTED)
        ignoreFieldLabel.setFont(ignoreFieldLabel.getFont().deriveFont(Font.BOLD, _F(8)))
        ignoreFieldLabel.setToolTipText("Ensures this field is NEVER stripped (exempts it)")

        self._ignoreField = JTextField(9)
        self._ignoreField.setToolTipText("Field name to keep (e.g. csrf_token)")
        self._ignoreField.setBackground(BG_HEADER)
        self._ignoreField.setForeground(TEXT_LIGHT)
        self._ignoreField.setCaretColor(TEXT_LIGHT)

        addIgnoreBtn = self._make_button("+ Add", GREEN)
        addIgnoreBtn.setMargin(_I(4, 10))
        addIgnoreBtn.addActionListener(lambda e: self._add_ignore_field())

        self._ignoreDropdown = JComboBox()
        self._ignoreDropdown.setToolTipText("Fields currently being ignored (not stripped)")
        self._ignoreDropdown.setPreferredSize(Dimension(_S(130), self._ignoreDropdown.getPreferredSize().height))

        deleteIgnoreBtn = self._make_button("Delete", DARK_RED)
        deleteIgnoreBtn.setMargin(_I(4, 10))
        deleteIgnoreBtn.setToolTipText("Remove the ignored field selected in the dropdown")
        deleteIgnoreBtn.addActionListener(lambda e: self._remove_ignore_field())

        clearIgnoreBtn = self._make_button("Clear All", DARK_RED)
        clearIgnoreBtn.setMargin(_I(4, 10))
        clearIgnoreBtn.setToolTipText("Clear all ignored fields")
        clearIgnoreBtn.addActionListener(lambda e: self._clear_all_ignore_fields())

        ignoreFieldPanel = JPanel(FlowLayout(FlowLayout.LEFT, 4, 0))
        ignoreFieldPanel.setBackground(BG_PANEL)
        ignoreFieldPanel.add(ignoreFieldLabel)
        ignoreFieldPanel.add(self._ignoreField)
        ignoreFieldPanel.add(addIgnoreBtn)
        ignoreFieldPanel.add(self._ignoreDropdown)
        ignoreFieldPanel.add(deleteIgnoreBtn)
        ignoreFieldPanel.add(clearIgnoreBtn)

        # Wrap Field Config in Stacked Layout
        fieldConfigPanel = JPanel(GridLayout(2, 1, 0, 4))
        fieldConfigPanel.setBackground(BG_PANEL)
        fieldConfigPanel.add(customFieldPanel)
        fieldConfigPanel.add(ignoreFieldPanel)

        buttonBar = JPanel(FlowLayout(FlowLayout.LEFT, 8, 8))
        buttonBar.setBackground(BG_PANEL)
        buttonBar.add(self.sendAllBtn)
        buttonBar.add(self.sendSelectedBtn)
        buttonBar.add(clearSelectedBtn)
        buttonBar.add(clearAllBtn)
        buttonBar.add(exportBtn)
        buttonBar.add(importBtn)
        buttonBar.add(fieldConfigPanel)

        _cap_text = "Capture: ON" if self.enabled else "Capture: OFF"
        _cap_color = GREEN if self.enabled else RED
        self.toggleBtn = JButton(_cap_text)
        self.toggleBtn.setOpaque(True)
        self.toggleBtn.setBorderPainted(False)
        self.toggleBtn.setFocusPainted(False)
        self.toggleBtn.setBackground(_cap_color)
        self.toggleBtn.setForeground(Color.WHITE)
        self.toggleBtn.setFont(self.toggleBtn.getFont().deriveFont(Font.BOLD, _F(8)))
        self.toggleBtn.setMargin(_I(4, 12))
        self.toggleBtn.addActionListener(lambda e: self._toggle_enabled(e))

        leftBar = JPanel(BorderLayout())
        leftBar.setBackground(BG_PANEL)
        leftBar.add(buttonBar, BorderLayout.WEST)

        nameLabel = SharedFlashyNameLabel("NoAuth By Faizan Kurawle")

        actionFlow = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 4))
        actionFlow.setBackground(BG_PANEL)
        actionFlow.add(self.stopBtn)
        actionFlow.add(self.resumeBtn)

        rightBar = JPanel(BorderLayout())
        rightBar.setBackground(BG_PANEL)
        rightBar.add(nameLabel, BorderLayout.NORTH)

        toggleFlow = JPanel(FlowLayout(FlowLayout.RIGHT, 0, 4))
        toggleFlow.setBackground(BG_PANEL)
        toggleFlow.add(self.toggleBtn)
        rightBar.add(toggleFlow, BorderLayout.CENTER)

        rightBar.add(actionFlow, BorderLayout.SOUTH)

        topBar = JPanel(BorderLayout())
        topBar.setBackground(BG_PANEL)
        topBar.add(leftBar, BorderLayout.WEST)
        topBar.add(rightBar, BorderLayout.EAST)

        profileLbl = JLabel("Active Profile:")
        profileLbl.setForeground(TEXT_LIGHT)
        profileLbl.setFont(profileLbl.getFont().deriveFont(Font.BOLD, _F(8)))

        self._profile_combo = JComboBox(self._profile_order_array())
        self._profile_combo.setBackground(BG_HEADER)
        self._profile_combo.setForeground(TEXT_LIGHT)
        self._profile_combo.setFont(Font("SansSerif", Font.BOLD, _S(8)))
        self._profile_combo.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6))
        self._profile_combo.setPreferredSize(_D(170, 26))
        self._profile_combo.addActionListener(ProfileComboListener(self))

        newProfileBtn = self._make_button("+ New Profile", BLUE_GRAY)
        newProfileBtn.addActionListener(lambda e: self._action_new_profile())

        renameProfileBtn = self._make_button("Rename", ORANGE)
        renameProfileBtn.addActionListener(lambda e: self._action_rename_profile())

        deleteProfileBtn = self._make_button("Delete Profile", DARK_RED)
        deleteProfileBtn.addActionListener(lambda e: self._action_delete_profile())

        profileBar = JPanel(FlowLayout(FlowLayout.LEFT, 10, 6))
        profileBar.setBackground(BG_PANEL)
        profileBar.add(profileLbl)
        profileBar.add(self._profile_combo)
        profileBar.add(newProfileBtn)
        profileBar.add(renameProfileBtn)
        profileBar.add(deleteProfileBtn)

        northWrapper = JPanel(BorderLayout())
        northWrapper.setBackground(BG_PANEL)
        northWrapper.add(profileBar, BorderLayout.NORTH)
        northWrapper.add(topBar, BorderLayout.CENTER)

        mainSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, tablePanel, editorWrapper)
        mainSplit.setResizeWeight(0.3)
        mainSplit.setBackground(BG_PANEL)

        self._panel = JPanel(BorderLayout())
        self._panel.setBackground(BG_PANEL)
        self._panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))
        self._panel.add(northWrapper, BorderLayout.NORTH)
        self._panel.add(mainSplit, BorderLayout.CENTER)

    def _titled_border(self, title):
        line = BorderFactory.createLineBorder(BG_HEADER)
        tb = BorderFactory.createTitledBorder(line, title)
        tb.setTitleColor(TEXT_LIGHT)
        return tb

    def _make_button(self, text, color):
        btn = JButton(text)
        btn.setOpaque(True)
        btn.setBorderPainted(False)
        btn.setFocusPainted(False)
        btn.setBackground(color)
        btn.setForeground(Color.WHITE)
        btn.setFont(btn.getFont().deriveFont(Font.BOLD))
        btn.setMargin(_I(6, 16))
        return btn

    def _make_nav_button(self, text):
        btn = JButton(text)
        btn.setOpaque(True)
        btn.setBorderPainted(False)
        btn.setFocusPainted(False)
        btn.setBackground(BLUE_GRAY)
        btn.setForeground(Color.WHITE)
        btn.setFont(btn.getFont().deriveFont(Font.BOLD))
        btn.setFont(btn.getFont().deriveFont(Font.BOLD))
        btn.setMargin(_I(2, 12))
        return btn

    def _view_to_model_row(self, viewRow):
        if viewRow < 0: return viewRow
        return self.table.convertRowIndexToModel(viewRow)

    def _on_row_select(self, event):
        if event.getValueIsAdjusting():
            return
        self._sync_editor_to_item(self.currentlyDisplayedItem)
        row = self._view_to_model_row(self.table.getSelectedRow())
        if row < 0:
            self.currentlyDisplayedItem = None
            self._update_history_label(None)
            return
        item = self.tableModel.getItem(row)
        self.currentlyDisplayedItem = item
        if item.history:
            item.historyIndex = len(item.history) - 1
            self._show_history_entry(item)
        else:
            self.requestViewer.setMessage(item.request, True)
            self.responseViewer.setMessage(EMPTY_BYTES, False)
            self._update_history_label(item)

    def _show_history_entry(self, item):
        entry = item.history[item.historyIndex]
        self.requestViewer.setMessage(entry["request"], True)
        if entry["response"] is not None:
            self.responseViewer.setMessage(entry["response"], False)
        else:
            self.responseViewer.setMessage(EMPTY_BYTES, False)
        self._update_history_label(item)

    def _update_history_label(self, item):
        if item is None or not item.history:
            self.historyLabel.setText("No history")
        else:
            self.historyLabel.setText("%d / %d" % (item.historyIndex + 1, len(item.history)))

    def _nav_prev(self, event):
        item = self.currentlyDisplayedItem
        if item is None or not item.history:
            return
        if item.historyIndex > 0:
            item.historyIndex -= 1
            self._show_history_entry(item)

    def _nav_next(self, event):
        item = self.currentlyDisplayedItem
        if item is None or not item.history:
            return
        if item.historyIndex < len(item.history) - 1:
            item.historyIndex += 1
            self._show_history_entry(item)

    def _sync_editor_to_item(self, item):
        if item is None:
            return
        try:
            if self.requestViewer.isMessageModified():
                newBytes = self.requestViewer.getMessage()
                item.request = newBytes
                requestInfo = self._helpers.analyzeRequest(item.httpService, newBytes)
                item.method = requestInfo.getMethod()
                item.url = str(requestInfo.getUrl())
                row = self.tableModel.items.index(item)
                self.tableModel.fireRowUpdated(row)
        except Exception as e:
            print("NoAuth sync error: %s" % e)

    def focus_request_viewer(self):
        self.requestViewer.getComponent().requestFocusInWindow()

    def show_queue_context_menu(self, event):
        row = self.table.rowAtPoint(event.getPoint())
        if row < 0:
            return
        if row not in self.table.getSelectedRows():
            self.table.setRowSelectionInterval(row, row)

        popup = JPopupMenu()
        repeater_item = JMenuItem("Send to Repeater")
        repeater_item.addActionListener(lambda e: self._send_selected_to_repeater())
        popup.add(repeater_item)
        popup.show(event.getComponent(), event.getX(), event.getY())

    def _send_selected_to_repeater(self):
        selected_rows = self.table.getSelectedRows()
        if not selected_rows:
            return
        model_indices = sorted([self._view_to_model_row(r) for r in selected_rows])
        for idx in model_indices:
            if not (0 <= idx < len(self.tableModel.items)):
                continue
            item = self.tableModel.getItem(idx)
            try:
                self._callbacks.sendToRepeater(
                    item.httpService.getHost(), item.httpService.getPort(),
                    item.httpService.getProtocol() == "https",
                    item.request, "NoAuth %d" % (idx + 1))
            except Exception as e:
                print("NoAuth sendToRepeater error (index %d): %s" % (idx, str(e)))

    # ---------- Export / Import ----------

    def _action_export_state(self):
        if not self.tableModel.items:
            JOptionPane.showMessageDialog(self._panel, "Nothing to export.")
            return

        chooser = JFileChooser()
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        safe_prof = re.sub(r'[^a-zA-Z0-9_\-]', '_', self._active_profile_name)
        chooser.setSelectedFile(java.io.File("noauth_%s_%s.json" % (safe_prof, timestamp)))
        result = chooser.showSaveDialog(self._panel)
        if result != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        if not path.lower().endswith(".json"):
            path += ".json"

        try:
            items_out = []
            for item in self.tableModel.items:
                history_out = []
                for h in item.history:
                    history_out.append({
                        "request": self._b64(h.get("request")),
                        "response": self._b64(h.get("response")),
                        "status": h.get("status"),
                        "time_ms": h.get("time_ms"),
                        "size": h.get("size"),
                    })
                items_out.append({
                    "host": item.httpService.getHost(),
                    "port": item.httpService.getPort(),
                    "protocol": item.httpService.getProtocol(),
                    "request": self._b64(item.request),
                    "response": self._b64(item.response),
                    "prev_status": item.prev_status,
                    "prev_size": item.prev_size,
                    "status": item.status,
                    "method": item.method,
                    "url": item.url,
                    "time_ms": item.time_ms,
                    "size": item.size,
                    "req_hash": item.req_hash,
                    "history": history_out,
                    "historyIndex": item.historyIndex,
                })

            with open(path, "w") as f:
                json.dump({"tool": "NoAuth", "version": 2, "profile": self._active_profile_name, "items": items_out}, f, indent=2)

            JOptionPane.showMessageDialog(self._panel, "Exported %d request(s) for profile '%s' to:\n%s" % (len(items_out), self._active_profile_name, path))
        except Exception as e:
            print("NoAuth export error: %s" % str(e))
            JOptionPane.showMessageDialog(self._panel, "Export failed: %s" % str(e))

    def _action_import_state(self):
        chooser = JFileChooser()
        result = chooser.showOpenDialog(self._panel)
        if result != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()

        try:
            with open(path, "r") as f:
                data = json.load(f)

            profile_name = data.get("profile", "Imported")
            if profile_name not in self._profiles:
                self._profiles[profile_name] = NA_Profile(profile_name)
                self._profile_order.append(profile_name)
            
            self._save_current_profile_state()
            self._active_profile_name = profile_name
            self.refresh_profile_combo()
            self.load_profile_into_ui(profile_name)

            imported = 0
            for entry in data.get("items", []):
                httpService = self._helpers.buildHttpService(
                    str(entry["host"]), int(entry["port"]), entry["protocol"] == "https")
                item = NA_QueueItem(httpService, self._unb64(entry.get("request")))
                item.response = self._unb64(entry.get("response"))
                item.prev_status = entry.get("prev_status", "")
                item.prev_size = entry.get("prev_size", "")
                item.status = entry.get("status", "queued")
                item.method = entry.get("method", "")
                item.url = entry.get("url", "")
                item.time_ms = entry.get("time_ms", "")
                item.size = entry.get("size", "")
                item.req_hash = entry.get("req_hash", None)
                item.historyIndex = entry.get("historyIndex", -1)
                for h in entry.get("history", []):
                    item.history.append({
                        "request": self._unb64(h.get("request")),
                        "response": self._unb64(h.get("response")),
                        "status": h.get("status"),
                        "time_ms": h.get("time_ms"),
                        "size": h.get("size"),
                    })
                self.tableModel.addItem(item)
                if item.req_hash:
                    self.seen_requests.add(item.req_hash)
                imported += 1

            JOptionPane.showMessageDialog(self._panel, "Imported %d request(s) into profile '%s'." % (imported, profile_name))
        except Exception as e:
            print("NoAuth import error: %s" % str(e))
            JOptionPane.showMessageDialog(self._panel, "Import failed: %s" % str(e))

    def _b64(self, raw_bytes):
        if raw_bytes is None: return None
        raw_str = "".join([chr(b & 0xFF) for b in raw_bytes])
        return base64.b64encode(raw_str)

    def _unb64(self, b64_str):
        if not b64_str: return None
        decoded = base64.b64decode(str(b64_str))
        return self._helpers.stringToBytes(decoded)

    # ---------- ITab ----------

    def getTabCaption(self):
        return "NoAuth"

    def getUiComponent(self):
        return self._panel

    # ---------- IMessageEditorController ----------

    def getHttpService(self):
        return self.currentlyDisplayedItem.httpService if self.currentlyDisplayedItem else None

    def getRequest(self):
        return self.currentlyDisplayedItem.request if self.currentlyDisplayedItem else None

    def getResponse(self):
        return self.currentlyDisplayedItem.response if self.currentlyDisplayedItem else None

    # ---------- IHttpListener ----------

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self.enabled: return
        # Capture when response is received to ensure prev_status and prev_size exist
        if messageIsRequest: return
        if toolFlag != self._callbacks.TOOL_REPEATER: return
        try:
            originalBytes = messageInfo.getRequest()

            preCheckInfo = self._helpers.analyzeRequest(messageInfo.getHttpService(), originalBytes)
            _dbg_method = preCheckInfo.getMethod()
            print("NoAuth DEBUG: captured method=[%s]" % _dbg_method)
            if _dbg_method.upper() == "OPTIONS": return

            strippedBytes = self._strip_auth(originalBytes)

            req_str = self._helpers.bytesToString(strippedBytes)
            parts = req_str.split("\r\n", 1)
            if parts:
                req_line = parts[0]
                if " HTTP/" in req_line:
                    base, proto = req_line.rsplit(" HTTP/", 1)
                    req_line = base + " HTTP/NORMALIZED"
                
                normalized_str = req_line + "\r\n" + (parts[1] if len(parts) > 1 else "")
                req_hash = hashlib.md5(normalized_str.encode('utf-8', 'ignore')).hexdigest()
            else:
                req_hash = hashlib.md5(strippedBytes).hexdigest()

            if req_hash in self.seen_requests: return
            self.seen_requests.add(req_hash)

            item = NA_QueueItem(messageInfo.getHttpService(), strippedBytes)
            item.prev_status = ""
            item.prev_size = ""
            if messageInfo.getResponse():
                try: 
                    resp = messageInfo.getResponse()
                    item.prev_status = str(self._helpers.analyzeResponse(resp).getStatusCode())
                    item.prev_size = str(len(resp))
                except: pass

            item.req_hash = req_hash
            requestInfo = self._helpers.analyzeRequest(messageInfo.getHttpService(), strippedBytes)
            item.method = requestInfo.getMethod()
            item.url = str(requestInfo.getUrl())

            self._add_item_async(item)
        except Exception as e:
            print("NoAuth capture error: %s" % e)

    def _add_item_async(self, item):
        SwingUtilities.invokeLater(lambda: self.tableModel.addItem(item))

    def ingest_request(self, httpService, requestBytes, originalResponseBytes=None):
        try:
            strippedBytes = self._strip_auth(requestBytes)

            req_str = self._helpers.bytesToString(strippedBytes)
            parts = req_str.split("\r\n", 1)
            if parts:
                req_line = parts[0]
                if " HTTP/" in req_line:
                    base, proto = req_line.rsplit(" HTTP/", 1)
                    req_line = base + " HTTP/NORMALIZED"

                normalized_str = req_line + "\r\n" + (parts[1] if len(parts) > 1 else "")
                req_hash = hashlib.md5(normalized_str.encode('utf-8', 'ignore')).hexdigest()
            else:
                req_hash = hashlib.md5(strippedBytes).hexdigest()

            if req_hash in self.seen_requests: return
            self.seen_requests.add(req_hash)

            item = NA_QueueItem(httpService, strippedBytes)
            item.prev_status = ""
            item.prev_size = ""
            if originalResponseBytes:
                try: 
                    item.prev_status = str(self._helpers.analyzeResponse(originalResponseBytes).getStatusCode())
                    item.prev_size = str(len(originalResponseBytes))
                except: pass

            item.req_hash = req_hash
            requestInfo = self._helpers.analyzeRequest(httpService, strippedBytes)
            item.method = requestInfo.getMethod()
            item.url = str(requestInfo.getUrl())

            self._add_item_async(item)
        except Exception as e:
            print("NoAuth manual ingest error: %s" % e)

    # ---------- Custom Strip / Ignore Management ----------

    def _add_custom_strip_field(self):
        name = self._customHeaderField.getText().strip()
        if not name: return
        lname = name.lower()
        if lname not in self.custom_strip_fields:
            self.custom_strip_fields.add(lname)
            self._customFieldsDropdown.addItem(name)

        print("NoAuth: will now strip custom field '%s' wherever it's found" % name)
        self._customHeaderField.setText("")

    def _remove_custom_strip_field(self):
        idx = self._customFieldsDropdown.getSelectedIndex()
        if idx < 0: return
        name = self._customFieldsDropdown.getItemAt(idx)
        self.custom_strip_fields.discard(name.strip().lower())
        self._customFieldsDropdown.removeItemAt(idx)

        print("NoAuth: stopped stripping custom field '%s'" % name)

    def _clear_all_custom_strip_fields(self):
        self.custom_strip_fields.clear()
        self._customFieldsDropdown.removeAllItems()
        print("NoAuth: Cleared all custom strip fields")

    def _add_ignore_field(self):
        name = self._ignoreField.getText().strip()
        if not name: return
        lname = name.lower()
        if lname not in self.custom_ignore_fields:
            self.custom_ignore_fields.add(lname)
            self._ignoreDropdown.addItem(name)

        print("NoAuth: will now IGNORE field '%s' (exempt from stripping)" % name)
        self._ignoreField.setText("")

    def _remove_ignore_field(self):
        idx = self._ignoreDropdown.getSelectedIndex()
        if idx < 0: return
        name = self._ignoreDropdown.getItemAt(idx)
        self.custom_ignore_fields.discard(name.strip().lower())
        self._ignoreDropdown.removeItemAt(idx)

        print("NoAuth: removed ignore exception for '%s'" % name)

    def _clear_all_ignore_fields(self):
        self.custom_ignore_fields.clear()
        self._ignoreDropdown.removeAllItems()
        print("NoAuth: Cleared all ignored fields")

    def _should_strip_header(self, name):
        n = (name or "").strip().lower()
        if n in self.custom_ignore_fields:
            return False
        if n in self.custom_strip_fields:
            return True
        if n in AUTH_HEADERS:
            return True
        return False

    def _should_strip_param(self, name):
        n = (name or "").strip().lower()
        if n in self.custom_ignore_fields:
            return False
        if n in self.custom_strip_fields:
            return True
        if n in AUTH_PARAM_NAMES:
            return True
        if "token" in n:
            return True
        return False

    # ---------- auth stripping ----------

    def _strip_auth(self, requestBytes):
        requestInfo = self._helpers.analyzeRequest(requestBytes)
        headers = list(requestInfo.getHeaders())
        newHeaders = []
        contentType = ""
        for i, h in enumerate(headers):
            if i == 0:
                newHeaders.append(self._strip_auth_from_request_line(h))
                continue
            if ":" not in h:
                newHeaders.append(h)
                continue
            name, _, value = h.partition(":")
            lname = name.strip().lower()
            
            if self._should_strip_header(lname):
                continue
                
            if lname == "content-type":
                contentType = value.strip().lower()
            newHeaders.append(name + ":" + self._strip_jwt_like_tokens(value))

        bodyOffset = requestInfo.getBodyOffset()
        body = requestBytes[bodyOffset:]
        body = self._strip_auth_from_body(body, contentType)
        return self._helpers.buildHttpMessage(newHeaders, body)

    def _strip_auth_from_request_line(self, line):
        try:
            parts = line.split(" ")
            if len(parts) < 2: return line
            method = parts[0]
            rest = " ".join(parts[1:])
            if " HTTP/" in rest:
                target, _, proto = rest.rpartition(" HTTP/")
                suffix = " HTTP/" + proto
            else:
                target = rest
                suffix = ""
            newTarget = self._strip_auth_from_url_target(target)
            newTarget = self._strip_jwt_like_tokens(newTarget)
            return method + " " + newTarget + suffix
        except Exception:
            return line

    def _strip_auth_from_url_target(self, target):
        if "?" not in target: return target
        path, _, qs = target.partition("?")
        newQs = self._strip_auth_from_params_string(qs)
        if newQs == qs: return target
        return (path + "?" + newQs) if newQs else path

    def _strip_auth_from_params_string(self, qs):
        if not qs: return qs
        pairs = qs.split("&")
        changed = False
        newPairs = []
        for pair in pairs:
            if pair and "=" in pair:
                k, _, v = pair.partition("=")
                try: decoded_k = unquote(k)
                except Exception: decoded_k = k
                
                if self._should_strip_param(decoded_k):
                    changed = True
                    continue 
            newPairs.append(pair)
        if not changed: return qs
        return "&".join(newPairs)

    def _strip_auth_from_body(self, bodyBytes, contentType):
        if bodyBytes is None or len(bodyBytes) == 0: return bodyBytes
        try: bodyStr = self._helpers.bytesToString(bodyBytes)
        except Exception: return bodyBytes

        try:
            if "json" in contentType:
                newStr = self._strip_auth_from_json_str(bodyStr)
            elif "x-www-form-urlencoded" in contentType:
                newStr = self._strip_auth_from_params_string(bodyStr)
            elif "multipart/form-data" in contentType:
                newStr = self._strip_auth_from_multipart(bodyStr)
            else:
                newStr = bodyStr
            newStr = self._strip_jwt_like_tokens(newStr)
        except Exception as e:
            print("NoAuth body auth-strip error: %s" % e)
            newStr = bodyStr

        try: return self._helpers.stringToBytes(newStr)
        except Exception: return bodyBytes

    def _strip_auth_from_json_str(self, text):
        try: 
            data = json.loads(text, object_pairs_hook=OrderedDict)
        except Exception: 
            return self._strip_auth_from_json_regex(text)
        redacted = self._redact_json_value(data)
        try: return json.dumps(redacted)
        except Exception: return text

    def _redact_json_value(self, value):
        if isinstance(value, dict):
            newDict = OrderedDict()
            for k, v in value.items():
                if isinstance(k, STRING_TYPES) and self._should_strip_param(k):
                    continue 
                newDict[k] = self._redact_json_value(v)
            return newDict
        if isinstance(value, (list, tuple)):
            return [self._redact_json_value(v) for v in value]
        return value

    def _strip_auth_from_json_regex(self, text):
        # Match keys preceded by a comma
        text = re.sub(r',\s*"([^"]+)"\s*:\s*"[^"]*"', 
                      lambda m: "" if self._should_strip_param(m.group(1)) else m.group(0), 
                      text, flags=re.IGNORECASE)
        # Match keys at start or followed by a comma
        text = re.sub(r'"([^"]+)"\s*:\s*"[^"]*"\s*,?\s*', 
                      lambda m: "" if self._should_strip_param(m.group(1)) else m.group(0), 
                      text, flags=re.IGNORECASE)
        return text

    def _strip_auth_from_multipart(self, text):
        pattern = re.compile(
            r'--[^\r\n]+\r\nContent-Disposition:\s*form-data;\s*name="([^"]+)"[^\r\n]*\r\n'
            r'(?:[^\r\n]+\r\n)*\r\n.*?\r\n(?=--)',
            re.IGNORECASE | re.DOTALL
        )
        def _sub(m):
            if self._should_strip_param(m.group(1)):
                return ""
            return m.group(0)
        return pattern.sub(_sub, text)

    def _strip_jwt_like_tokens(self, text):
        if not text: return text
        return JWT_REGEX.sub("", text)

    # ---------- Send All / Send Selected / Stop ----------

    def _set_send_buttons_enabled(self, enabled):
        def _toggle():
            self.sendAllBtn.setEnabled(enabled)
            self.sendSelectedBtn.setEnabled(enabled)
            self.stopBtn.setEnabled(not enabled)
            if not enabled:
                self.resumeBtn.setEnabled(False)
        SwingUtilities.invokeLater(_toggle)

    def _send_all(self, event):
        self._sync_editor_to_item(self.currentlyDisplayedItem)
        rows = list(range(self.tableModel.getRowCount()))
        if not rows: return
        self._clear_paused_rows()
        self._current_run_id += 1
        self._set_send_buttons_enabled(False)
        self._send_rows(rows, self._current_run_id)

    def _send_selected(self, event):
        self._sync_editor_to_item(self.currentlyDisplayedItem)
        rows = [self._view_to_model_row(r) for r in self.table.getSelectedRows()]
        if not rows: return
        self._clear_paused_rows()
        self._current_run_id += 1
        self._set_send_buttons_enabled(False)
        self._send_rows(rows, self._current_run_id)

    def _resume_sending(self, event):
        rows = self._paused_rows
        if not rows: return
        self._clear_paused_rows()
        self._current_run_id += 1
        self._set_send_buttons_enabled(False)
        self._send_rows(rows, self._current_run_id)

    def _action_stop_sending(self, event):
        self._current_run_id += 1 
        self._set_send_buttons_enabled(True)
        print("NoAuth: User aborted the active send queue.")

    def _set_paused_rows(self, rows):
        self._paused_rows = rows
        def _update():
            self.resumeBtn.setEnabled(bool(rows))
        SwingUtilities.invokeLater(_update)

    def _clear_paused_rows(self):
        self._paused_rows = []
        self.resumeBtn.setEnabled(False)

    def _send_rows(self, rows, run_id):
        t = threading.Thread(target=self._send_rows_worker, args=(rows, run_id))
        t.daemon = True
        t.start()

    def _send_rows_worker(self, rows, run_id):
        for idx, row in enumerate(rows):
            if self._current_run_id != run_id:
                self._set_paused_rows(rows[idx:])
                return
                
            item = self.tableModel.getItem(row)
            item.status = "sending"
            item.time_ms = ""
            item.size = ""
            self._fire_row_updated_async(row, item)

            start = JavaSystem.currentTimeMillis()
            try:
                result = self._callbacks.makeHttpRequest(item.httpService, item.request)
                elapsed = JavaSystem.currentTimeMillis() - start
                item.time_ms = str(elapsed)
                item.response = result.getResponse()
                if item.response is not None:
                    respInfo = self._helpers.analyzeResponse(item.response)
                    item.status = str(respInfo.getStatusCode())
                    item.size = str(len(item.response))
                else:
                    item.status = "no response"
                    item.size = "0"
            except Exception as e:
                item.time_ms = str(JavaSystem.currentTimeMillis() - start)
                item.status = "error: %s" % e

            item.history.append({
                "request": item.request,
                "response": item.response,
                "status": item.status,
                "time_ms": item.time_ms,
                "size": item.size,
            })
            item.historyIndex = len(item.history) - 1

            self._fire_row_updated_async(row, item)

        self._set_paused_rows([])
        def _finish():
            if self._current_run_id == run_id:
                self._set_send_buttons_enabled(True)
        SwingUtilities.invokeLater(_finish)

    def _fire_row_updated_async(self, row, item):
        def update():
            self.tableModel.fireRowUpdated(row)
            if item is self.currentlyDisplayedItem:
                if item.history:
                    item.historyIndex = len(item.history) - 1
                    self._show_history_entry(item)
                elif item.response is not None:
                    self.responseViewer.setMessage(item.response, False)
                else:
                    self.responseViewer.setMessage(EMPTY_BYTES, False)
        SwingUtilities.invokeLater(update)

    def _clear_selected(self, event):
        rows = [self._view_to_model_row(r) for r in self.table.getSelectedRows()]
        if not rows: return
        selectedItems = [self.tableModel.getItem(r) for r in rows]
        clearedCurrent = self.currentlyDisplayedItem in selectedItems
        for it in selectedItems:
            if it.req_hash is not None:
                self.seen_requests.discard(it.req_hash)
        self.tableModel.removeRows(rows)
        self._clear_paused_rows()
        if clearedCurrent:
            self.currentlyDisplayedItem = None
            self.requestViewer.setMessage(EMPTY_BYTES, True)
            self.responseViewer.setMessage(EMPTY_BYTES, False)
            self._update_history_label(None)

    def _clear_all(self, event):
        self.tableModel.clear()
        self.currentlyDisplayedItem = None
        self.seen_requests.clear()
        self._clear_paused_rows()
        self.requestViewer.setMessage(EMPTY_BYTES, True)
        self.responseViewer.setMessage(EMPTY_BYTES, False)
        self._update_history_label(None)

    def _toggle_enabled(self, event):
        self.enabled = not self.enabled
        if self.enabled:
            self.toggleBtn.setText("Capture: ON")
            self.toggleBtn.setBackground(GREEN)
            self.toggleBtn.setForeground(Color.WHITE)
        else:
            self.toggleBtn.setText("Capture: OFF")
            self.toggleBtn.setBackground(RED)
            self.toggleBtn.setForeground(Color.WHITE)

    # ---------- profile management ----------

    def _profile_order_array(self):
        return list(self._profile_order)

    def refresh_profile_combo(self):
        self._switching_profile = True
        try:
            self._profile_combo.removeAllItems()
            for name in self._profile_order:
                self._profile_combo.addItem(name)
            self._profile_combo.setSelectedItem(self._active_profile_name)
        finally:
            self._switching_profile = False

    def _save_current_profile_state(self):
        profile = self._profiles.get(self._active_profile_name)
        if profile is not None:
            profile.items = self.tableModel.items
            profile.seen_requests = self.seen_requests
            profile.paused_rows = self._paused_rows

    def on_profile_combo_changed(self):
        if self._switching_profile: return
        selected = self._profile_combo.getSelectedItem()
        if selected is None: return
        new_name = str(selected)
        if new_name == self._active_profile_name: return
        self._save_current_profile_state()
        self._active_profile_name = new_name
        self.load_profile_into_ui(new_name)

    def load_profile_into_ui(self, name):
        profile = self._profiles.get(name)
        if profile is None: return
        self._current_run_id += 1

        self.tableModel.items = profile.items
        self.tableModel.fireTableDataChanged()
        self.seen_requests = profile.seen_requests
        self._paused_rows = profile.paused_rows
        self.resumeBtn.setEnabled(bool(self._paused_rows))
        self.stopBtn.setEnabled(False)
        self.sendAllBtn.setEnabled(True)
        self.sendSelectedBtn.setEnabled(True)

        self.currentlyDisplayedItem = None
        self.requestViewer.setMessage(EMPTY_BYTES, True)
        self.responseViewer.setMessage(EMPTY_BYTES, False)
        self._update_history_label(None)

    def _action_new_profile(self):
        name = JOptionPane.showInputDialog(self._panel, "New profile name:")
        if name is None: return
        name = name.strip()
        if not name:
            JOptionPane.showMessageDialog(self._panel, "Profile name cannot be empty.")
            return
        if name in self._profiles:
            JOptionPane.showMessageDialog(self._panel, "A profile with that name already exists.")
            return
        self._save_current_profile_state()
        self._profiles[name] = NA_Profile(name)
        self._profile_order.append(name)
        self._active_profile_name = name
        self.refresh_profile_combo()
        self.load_profile_into_ui(name)

    def _action_rename_profile(self):
        old_name = self._active_profile_name
        if old_name == "Default":
            JOptionPane.showMessageDialog(self._panel, "The Default profile cannot be renamed.")
            return
        new_name = JOptionPane.showInputDialog(self._panel, "Rename profile '%s' to:" % old_name)
        if new_name is None: return
        new_name = new_name.strip()
        if not new_name or new_name in self._profiles:
            JOptionPane.showMessageDialog(self._panel, "Invalid or duplicate profile name.")
            return
        self._save_current_profile_state()
        profile = self._profiles.pop(old_name)
        profile.name = new_name
        self._profiles[new_name] = profile
        idx = self._profile_order.index(old_name)
        self._profile_order[idx] = new_name
        self._active_profile_name = new_name
        self.refresh_profile_combo()

    def _action_delete_profile(self):
        name = self._active_profile_name
        if name == "Default":
            JOptionPane.showMessageDialog(self._panel, "The Default profile cannot be deleted.")
            return
        confirm = JOptionPane.showConfirmDialog(
            self._panel,
            "Delete profile '%s' and all its captured requests?" % name,
            "Confirm Delete",
            JOptionPane.YES_NO_OPTION
        )
        if confirm != JOptionPane.YES_OPTION: return
        del self._profiles[name]
        self._profile_order.remove(name)
        self._active_profile_name = "Default"
        self.refresh_profile_combo()
        self.load_profile_into_ui("Default")


# ===========================================================================
# Sub-extension 2: JWT Attacker
# ===========================================================================

MODE_UNVERIFIED = "unverified"
MODE_NONE_ATTACK = "none_attack"
NONE_VARIANTS = ["none", "None", "NONE", "nOnE"]


def b64url_decode(s):
    s = str(s)
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def b64url_encode(data):
    return base64.urlsafe_b64encode(data).rstrip("=")


class JWT_QueueItem(object):
    def __init__(self, httpService, requestBytes, requestNumber=None):
        self.httpService = httpService
        self.request = requestBytes
        self.response = None
        self.prev_status = ""
        self.prev_size = ""
        self.status = "queued"
        self.method = ""
        self.url = ""
        self.variant = ""
        self.time_ms = ""
        self.size = ""
        self.requestNumber = requestNumber  
        self.history = []       
        self.historyIndex = -1  


class JWT_Profile(object):
    def __init__(self, name):
        self.name = name
        self.unverified_items = []
        self.unverified_seen = set()
        self.unverified_paused = []
        self.none_items = []
        self.none_seen = set()
        self.none_paused = []


class JWT_QueueTableModel(AbstractTableModel):
    columns = ["#", "Method", "URL", "Variant", "Prev Status", "Status", "Prev Size", "Size (bytes)", "Time (ms)"]

    def __init__(self, use_request_numbers=False):
        self.items = []
        self.use_request_numbers = use_request_numbers
        self._count_cb = None

    def getRowCount(self):
        return len(self.items)

    def getColumnCount(self):
        return len(self.columns)

    def getColumnName(self, col):
        return self.columns[col]

    def getValueAt(self, row, col):
        item = self.items[row]
        if col == 0:
            if self.use_request_numbers and item.requestNumber is not None:
                if row == 0 or self.items[row - 1].requestNumber != item.requestNumber:
                    return item.requestNumber
                return "-"
            return row + 1
        if col == 1: return item.method
        if col == 2: return item.url
        if col == 3: return item.variant
        if col == 4: return item.prev_status
        if col == 5: return item.status
        if col == 6: return item.prev_size
        if col == 7: return item.size
        if col == 8: return item.time_ms
        return ""

    def addItem(self, item):
        self.items.append(item)
        row = len(self.items) - 1
        self.fireTableRowsInserted(row, row)
        if self._count_cb: self._count_cb()

    def clear(self):
        del self.items[:]
        self.fireTableDataChanged()
        if self._count_cb: self._count_cb()

    def removeRows(self, rows):
        for row in sorted(set(rows), reverse=True):
            if 0 <= row < len(self.items):
                del self.items[row]
        self.fireTableDataChanged()
        if self._count_cb: self._count_cb()

    def getItem(self, row):
        return self.items[row]

    def fireRowUpdated(self, row):
        self.fireTableRowsUpdated(row, row)


class JWT_StatusCellRenderer(DefaultTableCellRenderer):
    def __init__(self):
        DefaultTableCellRenderer.__init__(self)
        self.setHorizontalAlignment(SwingConstants.CENTER)

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col)
        comp.setBackground(ROW_SELECTED if isSelected else (ROW_EVEN if row % 2 == 0 else ROW_ODD))
        comp.setForeground(Color.WHITE)
        comp.setFont(comp.getFont().deriveFont(Font.BOLD))
        return comp


class JWT_StripedCellRenderer(DefaultTableCellRenderer):
    def __init__(self):
        DefaultTableCellRenderer.__init__(self)
        self.setHorizontalAlignment(SwingConstants.CENTER)

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col)
        comp.setBackground(ROW_SELECTED if isSelected else (ROW_EVEN if row % 2 == 0 else ROW_ODD))
        
        # Keep it red even when selected
        if col == 4 or col == 6:  # Prev Status, Prev Size
            comp.setForeground(PREV_COL_COLOR)
        else:
            comp.setForeground(Color.WHITE)
            
        comp.setFont(comp.getFont().deriveFont(Font.BOLD))
        return comp



class ModePanel(IMessageEditorController):
    def __init__(self, callbacks, helpers, extender, accent_color, queue_title, use_request_numbers=False):
        self._callbacks = callbacks
        self._helpers = helpers
        self.extender = extender
        self.accent_color = accent_color
        self.queue_title = queue_title
        self.use_request_numbers = use_request_numbers
        self.tableModel = JWT_QueueTableModel(use_request_numbers=use_request_numbers)
        self.currentlyDisplayedItem = None
        self._seen = set()   
        self._current_run_id = 0 
        self._paused_rows = []   
        self._build_ui(callbacks, queue_title)

    def _build_ui(self, callbacks, queue_title):
        self.requestViewer = callbacks.createMessageEditor(self, True)
        self.responseViewer = callbacks.createMessageEditor(self, False)

        self.table = JTable(self.tableModel)
        self.table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self.table.getSelectionModel().addListSelectionListener(self._on_row_select)
        self.table.addMouseListener(QueueMouseAdapter(self))
        self.table.setRowHeight(_S(24))
        self.table.setShowGrid(False)
        self.table.setIntercellSpacing(Dimension(0, 0))
        self.table.setFillsViewportHeight(True)
        self.table.setBackground(ROW_EVEN)
        self.table.setForeground(TEXT_LIGHT)
        self.table.setSelectionBackground(ROW_SELECTED)
        self.table.setSelectionForeground(TEXT_LIGHT)
        self.table.setGridColor(BG_HEADER)

        header = self.table.getTableHeader()
        header.setFont(header.getFont().deriveFont(Font.BOLD))
        header.setBackground(BG_HEADER)
        header.setForeground(TEXT_LIGHT)
        header.setOpaque(True)
        headerRenderer = header.getDefaultRenderer()
        if isinstance(headerRenderer, DefaultTableCellRenderer):
            headerRenderer.setHorizontalAlignment(SwingConstants.CENTER)

        striped = JWT_StripedCellRenderer()
        self.table.setDefaultRenderer(JavaObject, striped)
        statusCol = self.table.getColumnModel().getColumn(5)
        statusCol.setCellRenderer(JWT_StatusCellRenderer())

        colModel = self.table.getColumnModel()
        colModel.getColumn(0).setPreferredWidth(35)   
        colModel.getColumn(1).setPreferredWidth(70)   
        colModel.getColumn(2).setPreferredWidth(200)  
        colModel.getColumn(3).setPreferredWidth(180)  
        colModel.getColumn(4).setPreferredWidth(75)   
        colModel.getColumn(5).setPreferredWidth(70)   
        colModel.getColumn(6).setPreferredWidth(75)   
        colModel.getColumn(7).setPreferredWidth(85)   
        colModel.getColumn(8).setPreferredWidth(75)  

        self.rowSorter = TableRowSorter(self.tableModel)
        self.rowSorter.setComparator(0, SharedNumericComparator())  
        self.rowSorter.setComparator(6, SharedNumericComparator())  
        self.rowSorter.setComparator(7, SharedNumericComparator())  
        self.rowSorter.setComparator(8, SharedNumericComparator())  
        self.table.setRowSorter(self.rowSorter)

        tableScroll = JScrollPane(self.table)
        tableScroll.setPreferredSize(_D(900, 220))
        tableScroll.getViewport().setBackground(ROW_EVEN)
        tableScroll.setBackground(BG_PANEL)

        # ---- Search bar ----
        jwt_searchLabel = JLabel("Search:")
        jwt_searchLabel.setForeground(TEXT_MUTED)
        jwt_searchLabel.setFont(jwt_searchLabel.getFont().deriveFont(Font.BOLD, _F(8)))

        self._jwt_search_field = JTextField(22)
        self._jwt_search_field.setBackground(BG_HEADER)
        self._jwt_search_field.setForeground(TEXT_LIGHT)
        self._jwt_search_field.setCaretColor(TEXT_LIGHT)
        self._jwt_search_field.setToolTipText("Filter rows by URL, Method, Attack, or Status")
        self._jwt_search_field.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(BLUE_GRAY, 1),
            BorderFactory.createEmptyBorder(2, 6, 2, 6)
        ))

        _jwt_sorter_ref = self.rowSorter
        _jwt_field     = self._jwt_search_field

        class _JWTSearchAction(ActionListener):
            def actionPerformed(self2, e):
                text = _jwt_field.getText().strip()
                if text:
                    try:
                        rf = RowFilter.regexFilter("(?i)" + re.escape(text))
                    except Exception:
                        rf = RowFilter.regexFilter("(?i)" + text)
                else:
                    rf = None
                _jwt_sorter_ref.setRowFilter(rf)

        _jwt_action = _JWTSearchAction()

        from javax.swing.event import DocumentListener as _DocListener2
        class _JWTDocListener(_DocListener2):
            def insertUpdate(self2, e):  _jwt_action.actionPerformed(None)
            def removeUpdate(self2, e):  _jwt_action.actionPerformed(None)
            def changedUpdate(self2, e): _jwt_action.actionPerformed(None)

        _jwt_field.addActionListener(_jwt_action)
        _jwt_field.getDocument().addDocumentListener(_JWTDocListener())

        jwt_clearBtn = JButton("x")
        jwt_clearBtn.setOpaque(True)
        jwt_clearBtn.setBorderPainted(False)
        jwt_clearBtn.setFocusPainted(False)
        jwt_clearBtn.setBackground(DARK_RED)
        jwt_clearBtn.setForeground(Color.WHITE)
        jwt_clearBtn.setFont(jwt_clearBtn.getFont().deriveFont(Font.BOLD, _F(8)))
        jwt_clearBtn.setMargin(_I(2, 6))
        jwt_clearBtn.setToolTipText("Clear search")

        class _JWTClearAction(ActionListener):
            def actionPerformed(self2, e):
                _jwt_field.setText("")
                _jwt_sorter_ref.setRowFilter(None)

        jwt_clearBtn.addActionListener(_JWTClearAction())

        jwt_searchBar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        jwt_searchBar.setBackground(BG_PANEL)
        jwt_searchBar.add(jwt_searchLabel)
        jwt_searchBar.add(self._jwt_search_field)
        jwt_searchBar.add(jwt_clearBtn)

        tablePanel = JPanel(BorderLayout())
        tablePanel.setBackground(BG_PANEL)
        tablePanel.setBorder(self._titled_border(queue_title))
        tablePanel.add(jwt_searchBar, BorderLayout.NORTH)
        tablePanel.add(tableScroll, BorderLayout.CENTER)
        # ---- end search bar ----

        prevBtn = self._make_nav_button("<")
        prevBtn.addActionListener(lambda e: self._nav_prev(e))
        nextBtn = self._make_nav_button(">")
        nextBtn.addActionListener(lambda e: self._nav_next(e))

        self.historyLabel = JLabel("No history", SwingConstants.CENTER)
        self.historyLabel.setForeground(TEXT_MUTED)
        self.historyLabel.setFont(self.historyLabel.getFont().deriveFont(Font.BOLD, _F(8)))

        navBar = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 4))
        navBar.setBackground(BG_PANEL)
        navBar.add(prevBtn)
        navBar.add(self.historyLabel)
        navBar.add(nextBtn)

        requestPanel = JPanel(BorderLayout())
        requestPanel.setBackground(BG_PANEL)
        requestPanel.add(navBar, BorderLayout.NORTH)
        requestPanel.add(self.requestViewer.getComponent(), BorderLayout.CENTER)

        editorSplit = JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                                  requestPanel,
                                  self.responseViewer.getComponent())
        editorSplit.setResizeWeight(0.5)
        editorSplit.setBackground(BG_PANEL)

        editorWrapper = JPanel(BorderLayout())
        editorWrapper.setBackground(BG_PANEL)
        editorWrapper.setBorder(self._titled_border("Request / Response"))
        editorWrapper.add(editorSplit, BorderLayout.CENTER)

        self.sendAllBtn = self._make_button("Send All", GREEN)
        self.sendAllBtn.addActionListener(lambda e: self._send_all(e))
        
        self.sendSelectedBtn = self._make_button("Send Selected", ORANGE)
        self.sendSelectedBtn.addActionListener(lambda e: self._send_selected(e))
        
        self.stopBtn = self._make_button("Stop", RED)
        self.stopBtn.setEnabled(False)
        self.stopBtn.addActionListener(lambda e: self._action_stop_sending(e))

        self.resumeBtn = self._make_button("Resume", QUEUED_COLOR)
        self.resumeBtn.setEnabled(False)
        self.resumeBtn.addActionListener(lambda e: self._resume_sending(e))

        clearSelectedBtn = self._make_button("Clear Selected", CLEAR_SELECTED_COLOR)
        clearSelectedBtn.addActionListener(lambda e: self._clear_selected(e))
        
        clearAllBtn = self._make_button("Clear All", RED)
        clearAllBtn.addActionListener(lambda e: self._clear_all(e))

        exportBtn = self._make_button("Export", BLUE_GRAY)
        exportBtn.addActionListener(lambda e: self._action_export_state())

        importBtn = self._make_button("Import", BLUE_GRAY)
        importBtn.addActionListener(lambda e: self._action_import_state())

        injectTokenBtn = self._make_button("Inject Token", INJECT_TOKEN_COLOR)
        injectTokenBtn.setToolTipText(
            "Paste a new/latest JWT and re-run Unverified Signature + None Attack using it")
        injectTokenBtn.addActionListener(lambda e: self._action_inject_token(e))

        buttonBar = JPanel(FlowLayout(FlowLayout.LEFT, 8, 8))
        buttonBar.setBackground(BG_PANEL)
        buttonBar.add(self.sendAllBtn)
        buttonBar.add(self.sendSelectedBtn)
        buttonBar.add(clearSelectedBtn)
        buttonBar.add(clearAllBtn)
        buttonBar.add(exportBtn)
        buttonBar.add(importBtn)
        buttonBar.add(injectTokenBtn)

        actionBar = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 4))
        actionBar.setBackground(BG_PANEL)
        actionBar.add(self.stopBtn)
        actionBar.add(self.resumeBtn)

        topBar = JPanel(BorderLayout())
        topBar.setBackground(BG_PANEL)
        topBar.setBorder(BorderFactory.createEmptyBorder(10, 0, 0, 0))
        topBar.add(buttonBar, BorderLayout.WEST)
        topBar.add(actionBar, BorderLayout.EAST)

        mainSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, tablePanel, editorWrapper)
        mainSplit.setResizeWeight(0.3)
        mainSplit.setBackground(BG_PANEL)

        self.panel = JPanel(BorderLayout())
        self.panel.setBackground(BG_PANEL)
        self.panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))
        self.panel.add(topBar, BorderLayout.NORTH)
        self.panel.add(mainSplit, BorderLayout.CENTER)

    def _titled_border(self, title):
        line = BorderFactory.createLineBorder(BG_HEADER)
        tb = BorderFactory.createTitledBorder(line, title)
        tb.setTitleColor(TEXT_LIGHT)
        return tb

    def _make_button(self, text, color):
        btn = JButton(text)
        btn.setOpaque(True)
        btn.setBorderPainted(False)
        btn.setFocusPainted(False)
        btn.setBackground(color)
        btn.setForeground(Color.WHITE)
        btn.setMargin(_I(6, 16))
        btn.setMargin(_I(6, 16))
        return btn

    def _make_nav_button(self, text):
        btn = JButton(text)
        btn.setOpaque(True)
        btn.setBorderPainted(False)
        btn.setFocusPainted(False)
        btn.setBackground(BLUE_GRAY)
        btn.setForeground(Color.WHITE)
        btn.setMargin(_I(2, 12))
        btn.setMargin(_I(2, 12))
        return btn

    def _view_to_model_row(self, viewRow):
        if viewRow < 0: return viewRow
        return self.table.convertRowIndexToModel(viewRow)

    def _on_row_select(self, event):
        if event.getValueIsAdjusting(): return
        self._sync_editor_to_item(self.currentlyDisplayedItem)
        row = self._view_to_model_row(self.table.getSelectedRow())
        if row < 0:
            self.currentlyDisplayedItem = None
            self._update_history_label(None)
            return
        item = self.tableModel.getItem(row)
        self.currentlyDisplayedItem = item
        if item.history:
            item.historyIndex = len(item.history) - 1
            self._show_history_entry(item)
        else:
            self.requestViewer.setMessage(item.request, True)
            self.responseViewer.setMessage(EMPTY_BYTES, False)
            self._update_history_label(item)

    def _show_history_entry(self, item):
        entry = item.history[item.historyIndex]
        self.requestViewer.setMessage(entry["request"], True)
        if entry["response"] is not None:
            self.responseViewer.setMessage(entry["response"], False)
        else:
            self.responseViewer.setMessage(EMPTY_BYTES, False)
        self._update_history_label(item)

    def _update_history_label(self, item):
        if item is None or not item.history:
            self.historyLabel.setText("No history")
        else:
            self.historyLabel.setText("%d / %d" % (item.historyIndex + 1, len(item.history)))

    def _nav_prev(self, event):
        item = self.currentlyDisplayedItem
        if item is None or not item.history: return
        if item.historyIndex > 0:
            item.historyIndex -= 1
            self._show_history_entry(item)

    def _nav_next(self, event):
        item = self.currentlyDisplayedItem
        if item is None or not item.history: return
        if item.historyIndex < len(item.history) - 1:
            item.historyIndex += 1
            self._show_history_entry(item)

    def _sync_editor_to_item(self, item):
        if item is None: return
        try:
            if self.requestViewer.isMessageModified():
                newBytes = self.requestViewer.getMessage()
                item.request = newBytes
                requestInfo = self._helpers.analyzeRequest(item.httpService, newBytes)
                item.method = requestInfo.getMethod()
                item.url = str(requestInfo.getUrl())
                row = self.tableModel.items.index(item)
                self.tableModel.fireRowUpdated(row)
        except Exception as e:
            print("JWT Attacker sync error: %s" % e)

    def focus_request_viewer(self):
        self.requestViewer.getComponent().requestFocusInWindow()

    def show_queue_context_menu(self, event):
        row = self.table.rowAtPoint(event.getPoint())
        if row < 0: return
        if row not in self.table.getSelectedRows():
            self.table.setRowSelectionInterval(row, row)

        popup = JPopupMenu()
        repeater_item = JMenuItem("Send to Repeater")
        repeater_item.addActionListener(lambda e: self._send_selected_to_repeater())
        popup.add(repeater_item)
        popup.show(event.getComponent(), event.getX(), event.getY())

    def _send_selected_to_repeater(self):
        selected_rows = self.table.getSelectedRows()
        if not selected_rows: return
        model_indices = sorted([self._view_to_model_row(r) for r in selected_rows])
        for idx in model_indices:
            if not (0 <= idx < len(self.tableModel.items)): continue
            item = self.tableModel.getItem(idx)
            try:
                self._callbacks.sendToRepeater(
                    item.httpService.getHost(), item.httpService.getPort(),
                    item.httpService.getProtocol() == "https",
                    item.request, "%s %d" % (self.queue_title, idx + 1))
            except Exception as e:
                print("JWT Attacker sendToRepeater error (index %d): %s" % (idx, str(e)))

    def _action_export_state(self):
        if not self.tableModel.items:
            JOptionPane.showMessageDialog(self.panel, "Nothing to export.")
            return

        chooser = JFileChooser()
        safe_title = self.queue_title.lower().replace(" ", "_")
        safe_prof = re.sub(r'[^a-zA-Z0-9_\-]', '_', self.extender._active_profile_name)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        chooser.setSelectedFile(java.io.File("jwt_%s_%s_%s.json" % (safe_title, safe_prof, timestamp)))
        result = chooser.showSaveDialog(self.panel)
        if result != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()
        if not path.lower().endswith(".json"):
            path += ".json"

        try:
            items_out = []
            for item in self.tableModel.items:
                history_out = []
                for h in item.history:
                    history_out.append({
                        "request": self._b64(h.get("request")),
                        "response": self._b64(h.get("response")),
                        "status": h.get("status"),
                        "time_ms": h.get("time_ms"),
                        "size": h.get("size"),
                    })
                items_out.append({
                    "host": item.httpService.getHost(),
                    "port": item.httpService.getPort(),
                    "protocol": item.httpService.getProtocol(),
                    "request": self._b64(item.request),
                    "response": self._b64(item.response),
                    "prev_status": item.prev_status,
                    "prev_size": item.prev_size,
                    "status": item.status,
                    "method": item.method,
                    "url": item.url,
                    "variant": item.variant,
                    "time_ms": item.time_ms,
                    "size": item.size,
                    "requestNumber": item.requestNumber,
                    "history": history_out,
                    "historyIndex": item.historyIndex,
                })

            with open(path, "w") as f:
                json.dump({"tool": "JWTAttacker", "queue_title": self.queue_title,
                           "version": 2, "profile": self.extender._active_profile_name, "items": items_out}, f, indent=2)

            JOptionPane.showMessageDialog(self.panel, "Exported %d request(s) for profile '%s' to:\n%s" % (len(items_out), self.extender._active_profile_name, path))
        except Exception as e:
            print("JWT Attacker export error: %s" % str(e))
            JOptionPane.showMessageDialog(self.panel, "Export failed: %s" % str(e))

    def _action_import_state(self):
        chooser = JFileChooser()
        result = chooser.showOpenDialog(self.panel)
        if result != JFileChooser.APPROVE_OPTION:
            return
        path = chooser.getSelectedFile().getAbsolutePath()

        try:
            with open(path, "r") as f:
                data = json.load(f)

            profile_name = data.get("profile", "Imported")
            
            if profile_name not in self.extender._profiles:
                self.extender._profiles[profile_name] = JWT_Profile(profile_name)
                self.extender._profile_order.append(profile_name)
                
            self.extender._save_current_profile_state()
            self.extender._active_profile_name = profile_name
            self.extender.refresh_profile_combo()
            self.extender.load_profile_into_ui(profile_name)

            imported = 0
            for entry in data.get("items", []):
                httpService = self._helpers.buildHttpService(
                    str(entry["host"]), int(entry["port"]), entry["protocol"] == "https")
                item = JWT_QueueItem(httpService, self._unb64(entry.get("request")),
                                      requestNumber=entry.get("requestNumber"))
                item.response = self._unb64(entry.get("response"))
                item.prev_status = entry.get("prev_status", "")
                item.prev_size = entry.get("prev_size", "")
                item.status = entry.get("status", "queued")
                item.method = entry.get("method", "")
                item.url = entry.get("url", "")
                item.variant = entry.get("variant", "")
                item.time_ms = entry.get("time_ms", "")
                item.size = entry.get("size", "")
                item.historyIndex = entry.get("historyIndex", -1)
                for h in entry.get("history", []):
                    item.history.append({
                        "request": self._unb64(h.get("request")),
                        "response": self._unb64(h.get("response")),
                        "status": h.get("status"),
                        "time_ms": h.get("time_ms"),
                        "size": h.get("size"),
                    })
                self.tableModel.addItem(item)
                
                fp = self.extender._item_fingerprint(item) if hasattr(self.extender, '_item_fingerprint') else None
                if fp:
                    self._seen.add(fp)
                imported += 1

            JOptionPane.showMessageDialog(self.panel, "Imported %d request(s) into profile '%s'." % (imported, profile_name))
        except Exception as e:
            print("JWT Attacker import error: %s" % str(e))
            JOptionPane.showMessageDialog(self.panel, "Import failed: %s" % str(e))

    def _action_inject_token(self, event):
        """Let the user paste a fresh/latest JWT, then re-run BOTH the
        Unverified-Signature attack and the None Attack (alg:none) for
        ALL requests currently in the queue."""
        if not self.tableModel.items:
            JOptionPane.showMessageDialog(
                self.panel, "Queue is empty. Nothing to inject into.",
                "Empty Queue", JOptionPane.WARNING_MESSAGE)
            return

        promptLabel = JLabel("Paste the new/latest JWT to inject (header.payload.signature):")
        promptLabel.setForeground(TEXT_LIGHT)

        tokenArea = JTextArea(4, 50)
        tokenArea.setLineWrap(True)
        tokenArea.setWrapStyleWord(True)
        tokenScroll = JScrollPane(tokenArea)

        dialogPanel = JPanel(BorderLayout(0, 6))
        dialogPanel.setBackground(BG_PANEL)
        dialogPanel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4))
        dialogPanel.add(promptLabel, BorderLayout.NORTH)
        dialogPanel.add(tokenScroll, BorderLayout.CENTER)

        result = JOptionPane.showConfirmDialog(
            self.panel, dialogPanel, "Inject Token into ALL Requests",
            JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE)
        if result != JOptionPane.OK_OPTION:
            return

        new_token = tokenArea.getText().strip()
        if not new_token:
            JOptionPane.showMessageDialog(self.panel, "No token entered.")
            return
        if len(new_token.split(".")) < 2:
            JOptionPane.showMessageDialog(
                self.panel,
                "That doesn't look like a valid JWT (expected header.payload[.signature]).",
                "Invalid token", JOptionPane.ERROR_MESSAGE)
            return

        try:
            unverified_n, none_n = self.extender.inject_token_into_all_requests(new_token)
            JOptionPane.showMessageDialog(
                self.panel,
                "Token injected into ALL requests.\nUpdated %d Unverified-Signature variant(s) and "
                "%d None-Attack variant(s) in place."
                % (unverified_n, none_n))
        except Exception as e:
            print("JWT Attacker inject-token error: %s" % str(e))
            JOptionPane.showMessageDialog(self.panel, "Inject failed: %s" % str(e),
                                           "Error", JOptionPane.ERROR_MESSAGE)

    def _b64(self, raw_bytes):
        if raw_bytes is None: return None
        raw_str = "".join([chr(b & 0xFF) for b in raw_bytes])
        return base64.b64encode(raw_str)

    def _unb64(self, b64_str):
        if not b64_str: return None
        decoded = base64.b64decode(str(b64_str))
        return self._helpers.stringToBytes(decoded)

    # ---------- IMessageEditorController ----------

    def getHttpService(self):
        return self.currentlyDisplayedItem.httpService if self.currentlyDisplayedItem else None

    def getRequest(self):
        return self.currentlyDisplayedItem.request if self.currentlyDisplayedItem else None

    def getResponse(self):
        return self.currentlyDisplayedItem.response if self.currentlyDisplayedItem else None

    # ---------- capture ----------

    def add_item(self, item):
        fp = self.extender._item_fingerprint(item)
        if fp in self._seen: return
        self._seen.add(fp)
        SwingUtilities.invokeLater(lambda: self.tableModel.addItem(item))

    # ---------- Send All / Send Selected / Stop ----------
    
    def _set_send_buttons_enabled(self, enabled):
        def _toggle():
            self.sendAllBtn.setEnabled(enabled)
            self.sendSelectedBtn.setEnabled(enabled)
            self.stopBtn.setEnabled(not enabled)
            if not enabled:
                self.resumeBtn.setEnabled(False)
        SwingUtilities.invokeLater(_toggle)

    def _send_all(self, event):
        self._sync_editor_to_item(self.currentlyDisplayedItem)
        rows = list(range(self.tableModel.getRowCount()))
        if not rows: return
        self._clear_paused_rows()
        self._current_run_id += 1
        self._set_send_buttons_enabled(False)
        self._send_rows(rows, self._current_run_id)

    def _send_selected(self, event):
        self._sync_editor_to_item(self.currentlyDisplayedItem)
        rows = [self._view_to_model_row(r) for r in self.table.getSelectedRows()]
        if not rows: return
        self._clear_paused_rows()
        self._current_run_id += 1
        self._set_send_buttons_enabled(False)
        self._send_rows(rows, self._current_run_id)

    def _resume_sending(self, event):
        rows = self._paused_rows
        if not rows: return
        self._clear_paused_rows()
        self._current_run_id += 1
        self._set_send_buttons_enabled(False)
        self._send_rows(rows, self._current_run_id)

    def _action_stop_sending(self, event):
        self._current_run_id += 1 
        self._set_send_buttons_enabled(True)

    def _set_paused_rows(self, rows):
        self._paused_rows = rows
        def _update():
            self.resumeBtn.setEnabled(bool(rows))
        SwingUtilities.invokeLater(_update)

    def _clear_paused_rows(self):
        self._paused_rows = []
        self.resumeBtn.setEnabled(False)

    def _send_rows(self, rows, run_id):
        t = threading.Thread(target=self._send_rows_worker, args=(rows, run_id))
        t.daemon = True
        t.start()

    def _send_rows_worker(self, rows, run_id):
        for idx, row in enumerate(rows):
            if self._current_run_id != run_id:
                self._set_paused_rows(rows[idx:])
                return
                
            item = self.tableModel.getItem(row)
            item.status = "sending"
            item.time_ms = ""
            item.size = ""
            self._fire_row_updated_async(row, item)

            start = JavaSystem.currentTimeMillis()
            try:
                result = self._callbacks.makeHttpRequest(item.httpService, item.request)
                elapsed = JavaSystem.currentTimeMillis() - start
                item.time_ms = str(elapsed)
                item.response = result.getResponse()
                if item.response is not None:
                    respInfo = self._helpers.analyzeResponse(item.response)
                    item.status = str(respInfo.getStatusCode())
                    item.size = str(len(item.response))
                else:
                    item.status = "no response"
                    item.size = "0"
            except Exception as e:
                item.time_ms = str(JavaSystem.currentTimeMillis() - start)
                item.status = "error"

            item.history.append({
                "request": item.request,
                "response": item.response,
                "status": item.status,
                "time_ms": item.time_ms,
                "size": item.size,
            })
            item.historyIndex = len(item.history) - 1

            self._fire_row_updated_async(row, item)

        self._set_paused_rows([])
        def _finish():
            if self._current_run_id == run_id:
                self._set_send_buttons_enabled(True)
        SwingUtilities.invokeLater(_finish)

    def _fire_row_updated_async(self, row, item):
        def update():
            self.tableModel.fireRowUpdated(row)
            if item is self.currentlyDisplayedItem:
                if item.history:
                    item.historyIndex = len(item.history) - 1
                    self._show_history_entry(item)
                elif item.response is not None:
                    self.responseViewer.setMessage(item.response, False)
                else:
                    self.responseViewer.setMessage(EMPTY_BYTES, False)
        SwingUtilities.invokeLater(update)

    def _clear_selected(self, event):
        rows = [self._view_to_model_row(r) for r in self.table.getSelectedRows()]
        if not rows: return
        selectedItems = [self.tableModel.getItem(r) for r in rows]
        clearedCurrent = self.currentlyDisplayedItem in selectedItems
        for item in selectedItems:
            fp = self.extender._item_fingerprint(item)
            self._seen.discard(fp)
        self.tableModel.removeRows(rows)
        self._clear_paused_rows()
        if clearedCurrent:
            self.currentlyDisplayedItem = None
            self.requestViewer.setMessage(EMPTY_BYTES, True)
            self.responseViewer.setMessage(EMPTY_BYTES, False)
            self._update_history_label(None)

    def _clear_all(self, event):
        self.tableModel.clear()
        self._seen.clear()
        self.currentlyDisplayedItem = None
        self._clear_paused_rows()
        self.requestViewer.setMessage(EMPTY_BYTES, True)
        self.responseViewer.setMessage(EMPTY_BYTES, False)
        self._update_history_label(None)

    def get_state(self):
        return (self.tableModel.items, self._seen, self._paused_rows)

    def load_state(self, items, seen, paused):
        self._current_run_id += 1
        self.tableModel.items = items
        self.tableModel.fireTableDataChanged()
        self._seen = seen
        self._paused_rows = paused
        self.resumeBtn.setEnabled(bool(self._paused_rows))
        self.stopBtn.setEnabled(False)
        self.sendAllBtn.setEnabled(True)
        self.sendSelectedBtn.setEnabled(True)

        self.currentlyDisplayedItem = None
        self.requestViewer.setMessage(EMPTY_BYTES, True)
        self.responseViewer.setMessage(EMPTY_BYTES, False)
        self._update_history_label(None)


class CreditOverlayPanel(JPanel):
    TAB_STRIP_HEIGHT = 32

    def __init__(self, tabbedPane, creditLabel, toggleBtn):
        JPanel.__init__(self)
        self.setOpaque(False)
        self.setLayout(None)
        self.tabbedPane = tabbedPane
        self.creditLabel = creditLabel
        self.toggleBtn = toggleBtn
        self.add(creditLabel)
        self.add(toggleBtn)
        self.add(tabbedPane)

    def doLayout(self):
        w = self.getWidth()
        h = self.getHeight()
        self.tabbedPane.setBounds(0, 0, w, h)

        prefs = self.creditLabel.getPreferredSize()
        margin = 12
        ly = max(0, (self.TAB_STRIP_HEIGHT - prefs.height) // 2)

        self.creditLabel.setBounds(max(0, w - prefs.width - margin), ly,
                                    prefs.width, prefs.height)

        btnPrefs = self.toggleBtn.getPreferredSize()
        self.toggleBtn.setBounds(max(0, w - btnPrefs.width - margin), ly + prefs.height,
                                  btnPrefs.width, btnPrefs.height)

    def getPreferredSize(self):
        tabPref = self.tabbedPane.getPreferredSize()
        return Dimension(tabPref.width, tabPref.height)


class JWTAttackerExtender(object):
    def _init_state(self):
        """Initialise all data-bearing state. Safe to skip on UI rebuild."""
        self.is_enabled = True
        self._capture_counter = 0
        self._profiles = {}
        self._profile_order = []
        self._active_profile_name = "Default"
        self._switching_profile = False
        default_profile = JWT_Profile("Default")
        self._profiles["Default"] = default_profile
        self._profile_order.append("Default")
        self._count_cb = None   # set by BurpExtender after init

    def get_request_count(self):
        """Total distinct captured requests across all profiles.
        Each capture spawns 1 unverified-sig variant + len(NONE_VARIANTS) alg:none
        variants that all share the same requestNumber - count the source
        request once, not once per variant row."""
        total = 0
        for p in self._profiles.values():
            nums = set()
            for item in p.unverified_items:
                if item.requestNumber is not None:
                    nums.add(item.requestNumber)
            for item in p.none_items:
                if item.requestNumber is not None:
                    nums.add(item.requestNumber)
            total += len(nums)
        return total

    def _build_ui(self, callbacks):
        """Build (or rebuild) the entire UI. State must already be set."""
        active_profile = self._profiles.get(self._active_profile_name)
        if active_profile is None:
            active_profile = self._profiles[self._profile_order[0]]

        self.toggleButton = JButton("Capture: ON" if self.is_enabled else "Capture: OFF")
        self.toggleButton.setOpaque(True)
        self.toggleButton.setBorderPainted(False)
        self.toggleButton.setFocusPainted(False)
        self.toggleButton.setBackground(GREEN if self.is_enabled else RED)
        self.toggleButton.setForeground(Color.WHITE)
        self.toggleButton.setFont(self.toggleButton.getFont().deriveFont(Font.BOLD, _F(8)))
        self.toggleButton.setMargin(_I(2, 8))
        self.toggleButton.addActionListener(lambda e: self._toggle_capture(e))

        self.unverifiedPanel = ModePanel(callbacks, self._helpers, self, QUEUED_COLOR,
                                          "Queued requests - Unverified Signature",
                                          use_request_numbers=False)
        self.noneAttackPanel = ModePanel(callbacks, self._helpers, self, ORANGE,
                                          "Queued requests - None Attack (x4)",
                                          use_request_numbers=True)

        self.unverifiedPanel.tableModel.items = active_profile.unverified_items
        self.unverifiedPanel._seen = active_profile.unverified_seen
        self.unverifiedPanel._paused_rows = active_profile.unverified_paused
        self.noneAttackPanel.tableModel.items = active_profile.none_items
        self.noneAttackPanel._seen = active_profile.none_seen
        self.noneAttackPanel._paused_rows = active_profile.none_paused
        # Wire count callbacks so tab titles stay updated
        _jwt_self = self
        self.unverifiedPanel.tableModel._count_cb = lambda: _jwt_self._count_cb() if _jwt_self._count_cb else None
        self.noneAttackPanel.tableModel._count_cb = lambda: _jwt_self._count_cb() if _jwt_self._count_cb else None

        self.tabs = JTabbedPane()
        self.tabs.addTab("Unverified Signature", self.unverifiedPanel.panel)
        self.tabs.addTab("None Attack", self.noneAttackPanel.panel)
        self.tabs.setBackground(BG_PANEL)
        self.tabs.setForeground(TEXT_LIGHT)

        nameLabel = SharedFlashyNameLabel("JWT Attacker By Faizan Kurawle")
        overlay = CreditOverlayPanel(self.tabs, nameLabel, self.toggleButton)
        overlay.setBackground(BG_PANEL)

        profileLbl = JLabel("Active Profile:")
        profileLbl.setForeground(TEXT_LIGHT)
        profileLbl.setFont(profileLbl.getFont().deriveFont(Font.BOLD, _F(8)))

        self._profile_combo = JComboBox(self._profile_order_array())
        self._profile_combo.setBackground(BG_HEADER)
        self._profile_combo.setForeground(TEXT_LIGHT)
        self._profile_combo.setFont(Font("SansSerif", Font.BOLD, _S(8)))
        self._profile_combo.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6))
        self._profile_combo.setPreferredSize(_D(170, 26))
        self._profile_combo.addActionListener(ProfileComboListener(self))

        newProfileBtn = self._make_profile_button("+ New Profile", BLUE_GRAY)
        newProfileBtn.addActionListener(lambda e: self._action_new_profile())

        renameProfileBtn = self._make_profile_button("Rename", ORANGE)
        renameProfileBtn.addActionListener(lambda e: self._action_rename_profile())

        deleteProfileBtn = self._make_profile_button("Delete Profile", DARK_RED)
        deleteProfileBtn.addActionListener(lambda e: self._action_delete_profile())

        profileBar = JPanel(FlowLayout(FlowLayout.LEFT, 10, 6))
        profileBar.setBackground(BG_PANEL)
        profileBar.add(profileLbl)
        profileBar.add(self._profile_combo)
        profileBar.add(newProfileBtn)
        profileBar.add(renameProfileBtn)
        profileBar.add(deleteProfileBtn)

        self._panel = JPanel(BorderLayout())
        self._panel.setBackground(BG_PANEL)
        self._panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))
        self._panel.add(profileBar, BorderLayout.NORTH)
        self._panel.add(overlay, BorderLayout.CENTER)

    def init(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._init_state()
        self._build_ui(callbacks)
        print("JWT Attacker (Repeater2 sub-tab) loaded.")

    def rebuild_ui(self):
        """Rebuild only the UI (after a scale change). State is preserved."""
        self._build_ui(self._callbacks)

    def _make_profile_button(self, text, color):
        btn = JButton(text)
        btn.setOpaque(True)
        btn.setBorderPainted(False)
        btn.setFocusPainted(False)
        btn.setBackground(color)
        btn.setForeground(Color.WHITE)
        btn.setFont(btn.getFont().deriveFont(Font.BOLD))
        btn.setMargin(_I(4, 12))
        return btn

    def _toggle_capture(self, event):
        self.is_enabled = not self.is_enabled
        if self.is_enabled:
            self.toggleButton.setText("Capture: ON")
            self.toggleButton.setBackground(GREEN)
        else:
            self.toggleButton.setText("Capture: OFF")
            self.toggleButton.setBackground(RED)

    def getTabCaption(self):
        return "JWT Attacker"

    def getUiComponent(self):
        return self._panel

    def _profile_order_array(self):
        return list(self._profile_order)

    def refresh_profile_combo(self):
        self._switching_profile = True
        try:
            self._profile_combo.removeAllItems()
            for name in self._profile_order:
                self._profile_combo.addItem(name)
            self._profile_combo.setSelectedItem(self._active_profile_name)
        finally:
            self._switching_profile = False

    def _save_current_profile_state(self):
        profile = self._profiles.get(self._active_profile_name)
        if profile is None: return
        (profile.unverified_items, profile.unverified_seen,
         profile.unverified_paused) = self.unverifiedPanel.get_state()
        (profile.none_items, profile.none_seen,
         profile.none_paused) = self.noneAttackPanel.get_state()

    def on_profile_combo_changed(self):
        if self._switching_profile: return
        selected = self._profile_combo.getSelectedItem()
        if selected is None: return
        new_name = str(selected)
        if new_name == self._active_profile_name: return
        self._save_current_profile_state()
        self._active_profile_name = new_name
        self.load_profile_into_ui(new_name)

    def load_profile_into_ui(self, name):
        profile = self._profiles.get(name)
        if profile is None: return
        self.unverifiedPanel.load_state(
            profile.unverified_items, profile.unverified_seen, profile.unverified_paused)
        self.noneAttackPanel.load_state(
            profile.none_items, profile.none_seen, profile.none_paused)

    def _action_new_profile(self):
        name = JOptionPane.showInputDialog(self._panel, "New profile name:")
        if name is None: return
        name = name.strip()
        if not name:
            JOptionPane.showMessageDialog(self._panel, "Profile name cannot be empty.")
            return
        if name in self._profiles:
            JOptionPane.showMessageDialog(self._panel, "A profile with that name already exists.")
            return
        self._save_current_profile_state()
        self._profiles[name] = JWT_Profile(name)
        self._profile_order.append(name)
        self._active_profile_name = name
        self.refresh_profile_combo()
        self.load_profile_into_ui(name)

    def _action_rename_profile(self):
        old_name = self._active_profile_name
        if old_name == "Default":
            JOptionPane.showMessageDialog(self._panel, "The Default profile cannot be renamed.")
            return
        new_name = JOptionPane.showInputDialog(self._panel, "Rename profile '%s' to:" % old_name)
        if new_name is None: return
        new_name = new_name.strip()
        if not new_name or new_name in self._profiles:
            JOptionPane.showMessageDialog(self._panel, "Invalid or duplicate profile name.")
            return
        self._save_current_profile_state()
        profile = self._profiles.pop(old_name)
        profile.name = new_name
        self._profiles[new_name] = profile
        idx = self._profile_order.index(old_name)
        self._profile_order[idx] = new_name
        self._active_profile_name = new_name
        self.refresh_profile_combo()

    def _action_delete_profile(self):
        name = self._active_profile_name
        if name == "Default":
            JOptionPane.showMessageDialog(self._panel, "The Default profile cannot be deleted.")
            return
        confirm = JOptionPane.showConfirmDialog(
            self._panel,
            "Delete profile '%s' and all its captured requests?" % name,
            "Confirm Delete",
            JOptionPane.YES_NO_OPTION
        )
        if confirm != JOptionPane.YES_OPTION: return
        del self._profiles[name]
        self._profile_order.remove(name)
        self._active_profile_name = "Default"
        self.refresh_profile_combo()
        self.load_profile_into_ui("Default")

    def _make_unverified_variant(self, parts):
        sig = parts[2] if len(parts) > 2 else ""
        if len(sig) > 7:
            new_sig = sig[:-7] + "abcdefg"
        else:
            new_sig = "abcdefg"
        new_token = parts[0] + "." + parts[1] + "." + new_sig
        return (new_token, "Unverified sig (...abcdefg)")

    def _make_none_variants(self, parts):
        header_b64 = parts[0]
        payload_b64 = parts[1]
        try: header_json = b64url_decode(header_b64)
        except Exception: header_json = None

        out = []
        for variant in NONE_VARIANTS:
            if header_json is not None:
                new_header_json, count = re.subn(
                    r'("alg"\s*:\s*")[^"]*(")',
                    r'\1' + variant + r'\2',
                    header_json,
                    count=1
                )
                if count == 0: new_header_json = header_json
                new_header_b64 = b64url_encode(new_header_json)
            else:
                new_header_b64 = header_b64
            new_token = new_header_b64 + "." + payload_b64 + "."
            out.append((new_token, "alg:%s, sig stripped" % variant))
        return out

    def _build_variant_request(self, originalBytes, oldToken, newToken):
        text = self._helpers.bytesToString(originalBytes)
        if oldToken not in text:
            raise Exception("JWT not found in request for substitution")
        # .replace() globally updates the old token anywhere it appears (header, parameter, body)
        newText = text.replace(oldToken, newToken)
        newBytes = self._helpers.stringToBytes(newText)
        return self._fix_content_length(newBytes)

    def _fix_content_length(self, requestBytes):
        requestInfo = self._helpers.analyzeRequest(requestBytes)
        headers = list(requestInfo.getHeaders())
        bodyOffset = requestInfo.getBodyOffset()
        body = requestBytes[bodyOffset:]

        newHeaders = []
        hasCL = False
        for h in headers:
            if h.lower().startswith("content-length:"):
                newHeaders.append("Content-Length: %d" % len(body))
                hasCL = True
            else:
                newHeaders.append(h)
        if not hasCL and len(body) > 0:
            newHeaders.append("Content-Length: %d" % len(body))

        return self._helpers.buildHttpMessage(newHeaders, body)

    def _queue_variants(self, panel, messageInfo, originalBytes, token, variants, request_number):
        prev_status = ""
        prev_size = ""
        if messageInfo.getResponse():
            try: 
                resp = messageInfo.getResponse()
                prev_status = str(self._helpers.analyzeResponse(resp).getStatusCode())
                prev_size = str(len(resp))
            except: pass

        for new_token, label in variants:
            try:
                newBytes = self._build_variant_request(originalBytes, token, new_token)
            except Exception as e:
                print("JWT Attacker variant build error: %s" % e)
                continue

            item = JWT_QueueItem(messageInfo.getHttpService(), newBytes, requestNumber=request_number)
            item.prev_status = prev_status
            item.prev_size = prev_size
            requestInfo = self._helpers.analyzeRequest(messageInfo.getHttpService(), newBytes)
            item.method = requestInfo.getMethod()
            item.url = str(requestInfo.getUrl())
            item.variant = label
            panel.add_item(item)

    def inject_token_into_all_requests(self, new_token):
        """Manually injects a fresh JWT into ALL captured requests across both queues,
        updating the Unverified-Signature and None Attack variants IN PLACE."""
        new_parts = new_token.split(".")
        if len(new_parts) < 2:
            raise Exception("Invalid JWT format - expected header.payload[.signature]")

        # Generate the new attack variants based on the pasted token
        uv_variant = self._make_unverified_variant(new_parts)
        none_variants = self._make_none_variants(new_parts)
        uv_token = uv_variant[0]

        # Build a lookup: alg value -> new token, for the None-Attack panel.
        # We match on the alg value extracted from the stored label instead of
        # the whole label string (or a dict keyed on the exact label), since
        # that's far more robust - it won't silently match nothing if the
        # label format ever drifts (e.g. across saved profiles / versions).
        none_token_by_alg = {}
        for v_token, v_label in none_variants:
            m = re.search(r'alg:([^,]*),', v_label)
            alg_key = m.group(1) if m else v_label
            none_token_by_alg[alg_key] = v_token

        def _apply_new_token(q_item, v_token, row_idx, panel):
            # This file's _build_variant_request does a plain string replace
            # and needs the OLD token explicitly - it doesn't auto-locate JWTs
            # like some other versions of this script. Find it via JWT_REGEX,
            # falling back to a looser pattern if the strict one (which
            # requires a literal "eyJ" prefix and literal dots) misses -
            # e.g. because the token sits in a URL-encoded parameter, or this
            # is an alg:none variant whose header no longer starts with eyJ.
            text = self._helpers.bytesToString(q_item.request)
            match = JWT_REGEX.search(text)
            if not match:
                match = LOOSE_JWT_REGEX.search(text)
            if not match:
                raise Exception("no JWT found in request to replace")
            old_token = match.group(0)

            new_v_token = v_token
            if '%2E' in old_token.upper():
                # Old token is URL-encoded in the request - encode the
                # replacement the same way so the plain-string replace matches.
                new_v_token = v_token.replace('.', '%2E')

            q_item.request = self._build_variant_request(q_item.request, old_token, new_v_token)
            q_item.status = "queued"
            q_item.response = None
            q_item.time_ms = ""
            q_item.size = ""
            q_item.prev_status = ""
            q_item.prev_size = ""
            q_item.history = []
            q_item.historyIndex = -1

            def _update_ui(row_idx=row_idx, updated_item=q_item, p=panel):
                p.tableModel.fireRowUpdated(row_idx)
                if updated_item is p.currentlyDisplayedItem:
                    p.requestViewer.setMessage(updated_item.request, True)
                    p.responseViewer.setMessage(EMPTY_BYTES, False)
                    p._update_history_label(updated_item)

            SwingUtilities.invokeLater(_update_ui)

        def update_unverified_panel(panel):
            # Every row in this panel IS the unverified-sig variant, so there's
            # nothing to match against - just update them all unconditionally.
            count = 0
            for i, q_item in enumerate(panel.tableModel.items):
                try:
                    _apply_new_token(q_item, uv_token, i, panel)
                    count += 1
                except Exception as e:
                    print("Update unverified-variant error for row %d: %s" % (i, e))
            return count

        def update_none_panel(panel):
            count = 0
            for i, q_item in enumerate(panel.tableModel.items):
                m = re.search(r'alg:([^,]*),', str(q_item.variant))
                alg_key = m.group(1) if m else None
                v_token = none_token_by_alg.get(alg_key)
                if v_token is None:
                    # Unknown/legacy label format - fall back to the first
                    # none-variant token rather than silently skipping the row.
                    v_token = none_variants[0][0]
                try:
                    _apply_new_token(q_item, v_token, i, panel)
                    count += 1
                except Exception as e:
                    print("Update none-variant error for row %d: %s" % (i, e))
            return count

        # Apply to all requests in both tabs
        unv_count = update_unverified_panel(self.unverifiedPanel)
        none_count = update_none_panel(self.noneAttackPanel)

        return (unv_count, none_count)

    def _item_fingerprint(self, item):
        try:
            req_info = self._helpers.analyzeRequest(item.httpService, item.request)
            url = req_info.getUrl()
            full_url = str(url) if url else item.url
        except Exception:
            full_url = item.url

        raw = self._helpers.bytesToString(item.request)
        normalized = re.sub(r"HTTP/[12](\.[01])?", "HTTP/NORMALIZED", raw)
        digest = hashlib.md5(normalized.encode("utf-8", "ignore")).hexdigest()

        return (item.method, full_url, item.variant, digest)

    def has_jwt(self, requestBytes):
        try:
            text = self._helpers.bytesToString(requestBytes)
            match = JWT_REGEX.search(text)
            if not match: return False
            return len(match.group(0).split(".")) >= 2
        except Exception:
            return False

    def ingest_request(self, messageInfo):
        try:
            originalBytes = messageInfo.getRequest()
            text = self._helpers.bytesToString(originalBytes)
            match = JWT_REGEX.search(text)
            if not match: return
            token = match.group(0)
            parts = token.split(".")
            if len(parts) < 2: return

            self._capture_counter += 1
            req_num = self._capture_counter

            unverified_variants = [self._make_unverified_variant(parts)]
            self._queue_variants(self.unverifiedPanel, messageInfo, originalBytes,
                                  token, unverified_variants, req_num)

            none_variants = self._make_none_variants(parts)
            self._queue_variants(self.noneAttackPanel, messageInfo, originalBytes,
                                  token, none_variants, req_num)
        except Exception as e:
            print("JWT Attacker manual ingest error: %s" % e)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not getattr(self, 'is_enabled', True): return
        # Capture when response is received to ensure prev_status exists
        if messageIsRequest: return
        if toolFlag != self._callbacks.TOOL_REPEATER: return
        try:
            originalBytes = messageInfo.getRequest()

            methodCheck = self._helpers.analyzeRequest(messageInfo.getHttpService(), originalBytes)
            _dbg_method = methodCheck.getMethod()
            print("JWT Attacker DEBUG: captured method=[%s]" % _dbg_method)
            if _dbg_method.upper() == "OPTIONS": return

            text = self._helpers.bytesToString(originalBytes)
            match = JWT_REGEX.search(text)
            if not match: return
            token = match.group(0)
            parts = token.split(".")
            if len(parts) < 2: return

            self._capture_counter += 1
            req_num = self._capture_counter

            unverified_variants = [self._make_unverified_variant(parts)]
            self._queue_variants(self.unverifiedPanel, messageInfo, originalBytes,
                                  token, unverified_variants, req_num)

            none_variants = self._make_none_variants(parts)
            self._queue_variants(self.noneAttackPanel, messageInfo, originalBytes,
                                  token, none_variants, req_num)
        except Exception as e:
            print("JWT Attacker capture error: %s" % e)


# ===========================================================================
# Sub-extension 3: AuthzTester
# ===========================================================================

class CapturedRequest(object):
    def __init__(self, request_bytes, host, port, protocol, url):
        self.request_bytes = request_bytes
        self.host = host
        self.port = port
        self.protocol = protocol
        self.url = url
        self.method = "GET"
        self.prev_status = ""
        self.prev_size_bytes = ""
        self.status = None
        self.time_ms = None
        self.size_bytes = None
        self.response_bytes = None
        self.last_sent_bytes = None
        self.dup_key = None  


class UserProfile(object):
    def __init__(self, name):
        self.name = name
        self.requests = []  


class StatusColorRenderer(DefaultTableCellRenderer):
    def __init__(self, extender):
        DefaultTableCellRenderer.__init__(self)
        self._extender = extender

    def getTableCellRendererComponent(self, table, value, isSelected, hasFocus, row, col):
        comp = DefaultTableCellRenderer.getTableCellRendererComponent(
            self, table, value, isSelected, hasFocus, row, col)
        ext = self._extender
        str_value = str(value) if value is not None else ""
        try: status_val = int(str_value)
        except Exception: status_val = None

        comp.setBorder(BorderFactory.createEmptyBorder(0, 8, 0, 8))
        comp.setHorizontalAlignment(JLabel.CENTER)
        comp.setFont(comp.getFont().deriveFont(Font.BOLD))

        if isSelected:
            comp.setBackground(ext._c_sel)
        else:
            comp.setBackground(ext._c_bg if row % 2 == 0 else ext._c_row_alt)

        # Permanent Red for Prev Status (3) and Prev Size (5)
        if col == 3 or col == 5:  
            comp.setForeground(ext._c_prev)
        elif not isSelected and col == 4: 
            if str_value == "sending...": comp.setForeground(ext._c_3xx)
            elif str_value == "error": comp.setForeground(ext._c_4xx)
            else: comp.setForeground(ext._c_2xx)
        else:
            comp.setForeground(Color.WHITE)
            
        return comp


class AZ_QueueTableModel(AbstractTableModel):
    COLUMNS = ["#", "Method", "URL", "Prev Status", "Status", "Prev Size", "Size (bytes)", "Time (ms)"]

    def __init__(self):
        self.items = []
        self._count_cb = None

    def setItems(self, items):
        self.items = items
        self.fireTableDataChanged()
        if self._count_cb: self._count_cb()

    def getRowCount(self): return len(self.items)
    def getColumnCount(self): return len(self.COLUMNS)
    def getColumnName(self, col): return self.COLUMNS[col]
    def isCellEditable(self, row, col): return False
    def getColumnClass(self, columnIndex): return String

    def getValueAt(self, row, col):
        req = self.items[row]
        if col == 0: return str(row + 1)
        if col == 1: return req.method
        if col == 2: return req.url
        if col == 3: return str(req.prev_status) if req.prev_status else ""
        if col == 4: return str(req.status) if req.status is not None else ""
        if col == 5: return str(req.prev_size_bytes) if req.prev_size_bytes else ""
        if col == 6: return str(req.size_bytes) if req.size_bytes is not None else ""
        if col == 7: return str(req.time_ms) if req.time_ms is not None else ""
        return ""

    def addItem(self, item):
        row = len(self.items) - 1
        self.fireTableRowsInserted(row, row)
        if self._count_cb: self._count_cb()

    def fireRowUpdated(self, row):
        self.fireTableRowsUpdated(row, row)

    def clear(self):
        self.fireTableDataChanged()
        if self._count_cb: self._count_cb()


class AuthTableModel(AbstractTableModel):
    COLUMNS = ["Type", "Name", "Value"]

    def __init__(self): self.rows = []
    def getRowCount(self): return len(self.rows)
    def getColumnCount(self): return len(self.COLUMNS)
    def getColumnName(self, col): return self.COLUMNS[col]
    def isCellEditable(self, row, col): return True
    def getColumnClass(self, columnIndex): return String

    def getValueAt(self, row, col): return self.rows[row][col]

    def setValueAt(self, value, row, col):
        self.rows[row][col] = value
        self.fireTableCellUpdated(row, col)

    def addRow(self):
        self.rows.append(["Header", "", ""])
        self.fireTableRowsInserted(len(self.rows) - 1, len(self.rows) - 1)

    def removeRow(self, row):
        del self.rows[row]
        self.fireTableRowsDeleted(row, row)

    def clear(self):
        self.rows = []
        self.fireTableDataChanged()

    def getData(self):
        return [list(r) for r in self.rows]

    def setData(self, data):
        self.rows = []
        for r in data:
            if len(r) == 3:
                self.rows.append(list(r))
            elif len(r) == 4:
                self.rows.append([r[1], r[2], r[3]])
        self.fireTableDataChanged()


class AuthZContextMenuFactory(IContextMenuFactory):
    def __init__(self, extender): self._extender = extender
    def createMenuItems(self, invocation):
        menu_list = ArrayList()
        item = JMenuItem(SendToAuthZAction(self._extender, invocation))
        item.setText("Send to AuthZ Tester")
        menu_list.add(item)
        return menu_list


class SendToAuthZAction(AbstractAction):
    def __init__(self, extender, invocation):
        AbstractAction.__init__(self, "Send to AuthZ Tester")
        self._extender = extender
        self._invocation = invocation

    def actionPerformed(self, event):
        try:
            messages = self._invocation.getSelectedMessages()
            if not messages: return
            for msg in messages:
                http_service = msg.getHttpService()
                request_bytes = msg.getRequest()
                self._extender.ingest_request(
                    request_bytes,
                    http_service.getHost(),
                    http_service.getPort(),
                    http_service.getProtocol(),
                    None,
                    msg.getResponse()
                )
            self._extender.refresh_queue_table()
        except Exception as e:
            self._extender.log("SendToAuthZAction error: %s" % str(e))


class SendToNoAuthAction(AbstractAction):
    def __init__(self, noauth_extender, invocation):
        AbstractAction.__init__(self, "Send to NoAuth")
        self._noauth = noauth_extender
        self._invocation = invocation

    def actionPerformed(self, event):
        try:
            messages = self._invocation.getSelectedMessages()
            if not messages: return
            for msg in messages:
                self._noauth.ingest_request(msg.getHttpService(), msg.getRequest(), msg.getResponse())
        except Exception as e:
            print("SendToNoAuthAction error: %s" % str(e))


class SendToJwtAttackerAction(AbstractAction):
    def __init__(self, jwt_extender, invocation):
        AbstractAction.__init__(self, "Send to JWT Attacker")
        self._jwt = jwt_extender
        self._invocation = invocation

    def actionPerformed(self, event):
        try:
            messages = self._invocation.getSelectedMessages()
            if not messages: return
            for msg in messages:
                self._jwt.ingest_request(msg)
        except Exception as e:
            print("SendToJwtAttackerAction error: %s" % str(e))


class CombinedContextMenuFactory(IContextMenuFactory):
    def __init__(self, noauth_extender, jwt_extender, authz_extender):
        self._noauth = noauth_extender
        self._jwt = jwt_extender
        self._authz = authz_extender

    def createMenuItems(self, invocation):
        menu_list = ArrayList()

        noauth_item = JMenuItem(SendToNoAuthAction(self._noauth, invocation))
        noauth_item.setText("Send to NoAuth")
        menu_list.add(noauth_item)

        authz_item = JMenuItem(SendToAuthZAction(self._authz, invocation))
        authz_item.setText("Send to AuthZ Tester")
        menu_list.add(authz_item)

        try:
            messages = invocation.getSelectedMessages()
            jwt_present = bool(messages) and any(
                self._jwt.has_jwt(msg.getRequest()) for msg in messages
            )
        except Exception:
            jwt_present = False

        if jwt_present:
            jwt_item = JMenuItem(SendToJwtAttackerAction(self._jwt, invocation))
            jwt_item.setText("Send to JWT Attacker")
            menu_list.add(jwt_item)

        return menu_list


class CommandDispatcher(ActionListener):
    def __init__(self, extender): self._extender = extender
    def actionPerformed(self, event): self._extender.handle_action(event.getActionCommand())

class ProfileComboListener(ActionListener):
    def __init__(self, extender): self._extender = extender
    def actionPerformed(self, event): self._extender.on_profile_combo_changed()

class AuthProfileComboListener(ActionListener):
    def __init__(self, extender): self._extender = extender
    def actionPerformed(self, event): self._extender.on_auth_profile_combo_changed()

class QueueSelectionListener(ListSelectionListener):
    def __init__(self, extender): self._extender = extender
    def valueChanged(self, event):
        if event.getValueIsAdjusting(): return
        self._extender.on_table_selection_changed()


class QueueMouseAdapter(MouseAdapter):
    def __init__(self, extender):
        MouseAdapter.__init__(self)
        self._extender = extender

    def mouseClicked(self, event):
        if event.getClickCount() == 2 and not event.isPopupTrigger():
            self._extender.focus_request_viewer()

    def mousePressed(self, event): self._maybe_show_popup(event)
    def mouseReleased(self, event): self._maybe_show_popup(event)

    def _maybe_show_popup(self, event):
        if event.isPopupTrigger():
            self._extender.show_queue_context_menu(event)


class GradientBannerPanel(JPanel):
    def __init__(self, layout, color_left, color_right):
        JPanel.__init__(self, layout)
        self._color_left = color_left
        self._color_right = color_right

    def paintComponent(self, g):
        g2 = g.create()
        try:
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
            w = self.getWidth()
            h = self.getHeight()
            gradient = GradientPaint(0, 0, self._color_left, w, 0, self._color_right)
            g2.setPaint(gradient)
            g2.fillRect(0, 0, w, h)
        finally:
            g2.dispose()


class ButtonHoverEffect(MouseAdapter):
    def __init__(self, button, normal_bg, hover_bg):
        MouseAdapter.__init__(self)
        self._button = button
        self._normal_bg = normal_bg
        self._hover_bg = hover_bg

    def mouseEntered(self, event):
        if self._button.isEnabled(): self._button.setBackground(self._hover_bg)

    def mouseExited(self, event):
        self._button.setBackground(self._normal_bg)


class AuthZTesterExtender(IContextMenuFactory, IMessageEditorController):
    def _init_state(self):
        """Initialise all data-bearing state. Safe to skip on UI rebuild."""
        self._c_bg = Color.decode("#1a1b1e")
        self._c_panel = Color.decode("#212327")
        self._c_fg = Color.decode("#d8d8d8")
        self._c_fg_dim = Color.decode("#8a8d93")
        self._c_sel = Color.decode("#5f5fed")
        self._c_grid = Color.decode("#34363b")
        self._c_banner = Color.decode("#15803d")
        self._c_banner2 = Color.decode("#0f5132")
        self._c_accent = Color.decode("#34d399")
        self._c_2xx = Color.decode("#4ade80")
        self._c_3xx = Color.decode("#f59e0b")
        self._c_4xx = Color.decode("#ef4444")
        self._c_btn_bg = Color.decode("#2a2d32")
        self._c_btn_hover = Color.decode("#3a3d44")
        self._c_btn_fg = Color.decode("#e4e4e4")
        self._c_field_bg = Color.decode("#1f2023")
        self._c_row_alt = Color.decode("#202226")
        self._c_prev = Color(255, 60, 60)

        self._lock = threading.Lock()

        self._profiles = {}
        self._profile_order = []
        self._active_profile_name = "Default"
        self._switching_profile = False

        self._auth_profiles = {}
        self._auth_profile_order = []
        self._active_auth_profile_name = "Default"
        self._switching_auth_profile = False

        self._capture_enabled = True
        self._dup_hashes = set()
        self._history_map = {}
        self._history_index = {}
        self._selected_row = -1
        self._current_run_id = 0

        self._editor_http_service = None
        self._editor_request_bytes = None
        self._editor_response_bytes = None

        default_profile = UserProfile("Default")
        self._profiles["Default"] = default_profile
        self._profile_order.append("Default")

        self._auth_profiles["Default"] = []
        self._auth_profile_order.append("Default")
        self._count_cb = None   # set by BurpExtender after init

    def get_request_count(self):
        """Total requests across all profiles."""
        return sum(len(p.requests) for p in self._profiles.values())

    def init(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._init_state()
        self._build_ui()
        self.log("AuthZ Tester (Repeater2 sub-tab) loaded successfully.")

    def rebuild_ui(self):
        """Rebuild only the UI (after a scale change). State is preserved."""
        self._build_ui()

    def getTabCaption(self): return "AuthzTester"
    def getUiComponent(self): return self._main_panel
    def getHttpService(self): return self._editor_http_service
    def getRequest(self): return self._editor_request_bytes
    def getResponse(self): return self._editor_response_bytes

    def log(self, msg):
        try: self._callbacks.printOutput(str(msg))
        except Exception: pass

    def _make_button(self, text, action_command, accent=None):
        btn = JButton(text)
        btn.setBackground(self._c_btn_bg)
        btn.setForeground(self._c_btn_fg)
        btn.setFont(Font("SansSerif", Font.BOLD, _S(8)))
        btn.setFocusPainted(False)
        btn.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR))
        stripe_color = accent if accent is not None else self._c_grid
        btn.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(0, 3, 0, 0, stripe_color),
                BorderFactory.createLineBorder(self._c_grid, 1)
            ),
            BorderFactory.createEmptyBorder(5, 12, 5, 14)
        ))
        btn.setActionCommand(action_command)
        btn.addActionListener(CommandDispatcher(self))
        btn.addMouseListener(ButtonHoverEffect(btn, self._c_btn_bg, self._c_btn_hover))
        return btn

    def _section_border(self, title):
        line = BorderFactory.createLineBorder(self._c_grid, 1)
        titled = BorderFactory.createTitledBorder(
            line, title, TitledBorder.LEADING, TitledBorder.TOP,
            Font("SansSerif", Font.BOLD, _S(8)), self._c_accent
        )
        return BorderFactory.createCompoundBorder(
            titled, BorderFactory.createEmptyBorder(6, 8, 8, 8)
        )

    def _populate_auth_profile_combo(self):
        if not hasattr(self, '_auth_profile_combo'):
            return
        self._auth_profile_combo.removeAllItems()
        self._auth_profile_combo.addItem("") 
        for name in self._profile_order:
            self._auth_profile_combo.addItem(name)

    def _build_ui(self):
        self._main_panel = JPanel(BorderLayout(0, 8))
        self._main_panel.setBackground(self._c_bg)
        self._main_panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8))

        banner = GradientBannerPanel(BorderLayout(), self._c_banner, self._c_banner2)
        banner.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createMatteBorder(0, 0, 3, 0, self._c_accent),
            BorderFactory.createEmptyBorder(10, 16, 10, 16)
        ))

        west_profile_panel = JPanel(FlowLayout(FlowLayout.LEFT, 10, 4))
        west_profile_panel.setOpaque(False)

        lbl = JLabel("Active Profile")
        lbl.setForeground(Color.WHITE)
        lbl.setFont(Font("SansSerif", Font.BOLD, _S(8)))
        west_profile_panel.add(lbl)

        self._profile_combo = JComboBox(self._profile_order_array())
        self._profile_combo.setBackground(self._c_field_bg)
        self._profile_combo.setForeground(Color.WHITE)
        self._profile_combo.setFont(Font("SansSerif", Font.BOLD, _S(8)))
        self._profile_combo.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6))
        self._profile_combo.setPreferredSize(_D(170, 26))
        self._profile_combo.addActionListener(ProfileComboListener(self))
        west_profile_panel.add(self._profile_combo)

        west_profile_panel.add(self._make_button("+ New Profile", "NEW_PROFILE", accent=self._c_2xx))
        west_profile_panel.add(self._make_button("Rename", "RENAME_PROFILE", accent=self._c_3xx))
        west_profile_panel.add(self._make_button("Delete Profile", "DELETE_PROFILE", accent=self._c_4xx))

        banner.add(west_profile_panel, BorderLayout.WEST)

        self._capture_checkbox = JCheckBox("Capture", self._capture_enabled)
        self._capture_checkbox.setOpaque(False)
        self._capture_checkbox.setForeground(Color.WHITE)
        self._capture_checkbox.setFont(Font("SansSerif", Font.BOLD, _S(8)))
        self._capture_checkbox.setFocusPainted(False)
        self._capture_checkbox.setActionCommand("TOGGLE_CAPTURE")
        self._capture_checkbox.addActionListener(CommandDispatcher(self))
        cap_panel = JPanel(FlowLayout(FlowLayout.RIGHT, 0, 0))
        cap_panel.setOpaque(False)
        cap_panel.add(self._capture_checkbox)

        name_label = SharedFlashyNameLabel("AuthZ Tester By Faizan Kurawle")

        self._resume_button = self._make_button("Resume", "RESUME_SENDING", accent=self._c_3xx)
        self._stop_button = self._make_button("Stop", "STOP_SENDING", accent=self._c_4xx)
        self._stop_button.setEnabled(False)
        action_flow = JPanel(FlowLayout(FlowLayout.RIGHT, 6, 4))
        action_flow.setOpaque(False)
        action_flow.add(self._stop_button)
        action_flow.add(self._resume_button)

        right_box = JPanel(BorderLayout())
        right_box.setOpaque(False)
        right_box.add(name_label, BorderLayout.NORTH)
        right_box.add(cap_panel, BorderLayout.CENTER)
        right_box.add(action_flow, BorderLayout.SOUTH)
        banner.add(right_box, BorderLayout.EAST)

        self._main_panel.add(banner, BorderLayout.NORTH)

        self._table_model = AZ_QueueTableModel()
        _az_self = self
        self._table_model._count_cb = lambda: _az_self._count_cb() if _az_self._count_cb else None
        self._table = JTable(self._table_model)
        self._table.setBackground(self._c_bg)
        self._table.setForeground(self._c_fg)
        self._table.setGridColor(self._c_grid)
        self._table.setSelectionBackground(self._c_sel)
        self._table.setSelectionForeground(Color.WHITE)
        self._table.setAutoCreateRowSorter(True)
        self._table.setFillsViewportHeight(True)
        self._table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)
        self._table.setRowHeight(_S(28))
        self._table.setShowVerticalLines(False)
        self._table.setShowHorizontalLines(True)
        self._table.setIntercellSpacing(Dimension(0, 1))
        self._table.setFont(Font("SansSerif", Font.BOLD, _S(8)))
        header = self._table.getTableHeader()
        header.setBackground(self._c_panel)
        header.setForeground(self._c_fg)
        header.setFont(Font("SansSerif", Font.BOLD, _S(8)))
        header.setReorderingAllowed(False)
        header.setBorder(BorderFactory.createMatteBorder(0, 0, 2, 0, self._c_accent))
        header.setPreferredSize(Dimension(header.getPreferredSize().width, _S(32)))

        status_renderer = StatusColorRenderer(self)
        for col_index in range(self._table_model.getColumnCount()):
            self._table.getColumnModel().getColumn(col_index).setCellRenderer(status_renderer)

        self._table.getSelectionModel().addListSelectionListener(QueueSelectionListener(self))
        self._table.addMouseListener(QueueMouseAdapter(self))

        table_scroll = JScrollPane(self._table)
        table_scroll.getViewport().setBackground(self._c_bg)
        table_scroll.setBorder(BorderFactory.createLineBorder(self._c_grid, 1))

        # ---- Search bar ----
        az_searchLabel = JLabel("Search:")
        az_searchLabel.setForeground(self._c_fg_dim)
        az_searchLabel.setFont(Font("SansSerif", Font.BOLD, _S(8)))

        self._az_search_field = JTextField(22)
        self._az_search_field.setBackground(self._c_field_bg)
        self._az_search_field.setForeground(self._c_fg)
        self._az_search_field.setCaretColor(self._c_fg)
        self._az_search_field.setToolTipText("Filter rows by URL, Method, or Status")
        self._az_search_field.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(self._c_accent, 1),
            BorderFactory.createEmptyBorder(2, 6, 2, 6)
        ))

        _az_table = self._table
        _az_field  = self._az_search_field

        class _AZSearchAction(ActionListener):
            def actionPerformed(self2, e):
                text = _az_field.getText().strip()
                sorter = _az_table.getRowSorter()
                if sorter is None:
                    return
                if text:
                    try:
                        rf = RowFilter.regexFilter("(?i)" + re.escape(text))
                    except Exception:
                        rf = RowFilter.regexFilter("(?i)" + text)
                else:
                    rf = None
                sorter.setRowFilter(rf)

        _az_action = _AZSearchAction()

        from javax.swing.event import DocumentListener as _DocListener3
        class _AZDocListener(_DocListener3):
            def insertUpdate(self2, e):  _az_action.actionPerformed(None)
            def removeUpdate(self2, e):  _az_action.actionPerformed(None)
            def changedUpdate(self2, e): _az_action.actionPerformed(None)

        _az_field.addActionListener(_az_action)
        _az_field.getDocument().addDocumentListener(_AZDocListener())

        az_clearBtn = JButton("x")
        az_clearBtn.setOpaque(True)
        az_clearBtn.setBorderPainted(False)
        az_clearBtn.setFocusPainted(False)
        az_clearBtn.setBackground(self._c_4xx)
        az_clearBtn.setForeground(Color.WHITE)
        az_clearBtn.setFont(Font("SansSerif", Font.BOLD, _S(8)))
        az_clearBtn.setMargin(_I(2, 6))
        az_clearBtn.setToolTipText("Clear search")

        class _AZClearAction(ActionListener):
            def actionPerformed(self2, e):
                _az_field.setText("")
                sorter = _az_table.getRowSorter()
                if sorter is not None:
                    sorter.setRowFilter(None)

        az_clearBtn.addActionListener(_AZClearAction())

        az_searchBar = JPanel(FlowLayout(FlowLayout.LEFT, 6, 4))
        az_searchBar.setBackground(self._c_bg)
        az_searchBar.add(az_searchLabel)
        az_searchBar.add(self._az_search_field)
        az_searchBar.add(az_clearBtn)
        # ---- end search bar ----

        queue_buttons = JPanel(FlowLayout(FlowLayout.LEFT, 8, 8))
        queue_buttons.setBackground(self._c_bg)
        self._send_all_button = self._make_button("Send All", "SEND_ALL", accent=self._c_2xx)
        self._send_selected_button = self._make_button("Send Selected", "SEND_SELECTED", accent=self._c_2xx)
        
        queue_buttons.add(self._send_all_button)
        queue_buttons.add(self._send_selected_button)
        queue_buttons.add(self._make_button("Remove Selected", "REMOVE_SELECTED", accent=self._c_4xx))
        queue_buttons.add(self._make_button("Clear All", "CLEAR_QUEUE", accent=self._c_4xx))
        queue_buttons.add(self._make_button("Export State", "EXPORT_STATE", accent=self._c_3xx))
        queue_buttons.add(self._make_button("Import State", "IMPORT_STATE", accent=self._c_3xx))

        queue_panel = JPanel(BorderLayout(0, 6))
        queue_panel.setBackground(self._c_bg)
        queue_panel.setBorder(self._section_border("Request Queue"))
        queue_panel.add(az_searchBar, BorderLayout.NORTH)
        queue_panel.add(table_scroll, BorderLayout.CENTER)
        queue_panel.add(queue_buttons, BorderLayout.SOUTH)

        # -------------------------------------------------------------
        # AUTH MATERIAL INJECTOR SECTION
        # -------------------------------------------------------------

        authProfileLbl = JLabel("Auth Profile:")
        authProfileLbl.setForeground(Color.WHITE)
        authProfileLbl.setFont(Font("SansSerif", Font.BOLD, _S(8)))

        self._auth_profile_combo = JComboBox(self._auth_profile_order_array())
        self._auth_profile_combo.setBackground(self._c_field_bg)
        self._auth_profile_combo.setForeground(Color.WHITE)
        self._auth_profile_combo.setFont(Font("SansSerif", Font.BOLD, _S(8)))
        self._auth_profile_combo.setBorder(BorderFactory.createEmptyBorder(2, 6, 2, 6))
        self._auth_profile_combo.setPreferredSize(_D(160, 26))
        self._auth_profile_combo.addActionListener(AuthProfileComboListener(self))

        newAuthBtn = self._make_button("+ New Profile", "NEW_AUTH_PROFILE", accent=self._c_2xx)
        renAuthBtn = self._make_button("Rename", "RENAME_AUTH_PROFILE", accent=self._c_3xx)
        delAuthBtn = self._make_button("Delete Profile", "DELETE_AUTH_PROFILE", accent=self._c_4xx)

        newAuthBtn.setMargin(_I(2, 8))
        renAuthBtn.setMargin(_I(2, 8))
        delAuthBtn.setMargin(_I(2, 8))

        auth_profile_bar = JPanel(FlowLayout(FlowLayout.LEFT, 10, 4))
        auth_profile_bar.setOpaque(False)
        auth_profile_bar.add(authProfileLbl)
        auth_profile_bar.add(self._auth_profile_combo)
        auth_profile_bar.add(newAuthBtn)
        auth_profile_bar.add(renAuthBtn)
        auth_profile_bar.add(delAuthBtn)

        auth_hint = JLabel("Low-privilege headers/cookies/params to inject before sending")
        auth_hint.setForeground(self._c_fg_dim)
        auth_hint.setFont(Font("SansSerif", Font.BOLD | Font.ITALIC, _S(8)))
        auth_hint.setBorder(BorderFactory.createEmptyBorder(0, 6, 2, 0))

        top_auth_panel = JPanel(BorderLayout(0, 4))
        top_auth_panel.setBackground(self._c_bg)
        top_auth_panel.add(auth_profile_bar, BorderLayout.NORTH)
        top_auth_panel.add(auth_hint, BorderLayout.SOUTH)
        top_auth_panel.setBorder(BorderFactory.createEmptyBorder(0, 0, 4, 0))

        self._auth_table_model = AuthTableModel()
        self._auth_table = JTable(self._auth_table_model)
        self._auth_table.setBackground(self._c_field_bg)
        self._auth_table.setForeground(self._c_fg)
        self._auth_table.setGridColor(self._c_grid)
        self._auth_table.setSelectionBackground(self._c_sel)
        self._auth_table.setSelectionForeground(Color.WHITE)
        self._auth_table.setRowHeight(_S(30))
        
        self._auth_table.setFont(Font("Monospaced", Font.BOLD, _S(8)))
        self._auth_table.setFillsViewportHeight(True)
        self._auth_table.putClientProperty("terminateEditOnFocusLost", True)

        auth_header = self._auth_table.getTableHeader()
        auth_header.setBackground(self._c_panel)
        auth_header.setForeground(self._c_fg)
        auth_header.setFont(Font("SansSerif", Font.BOLD, _S(8)))
        
        renderer = auth_header.getDefaultRenderer()
        if hasattr(renderer, 'setHorizontalAlignment'):
            renderer.setHorizontalAlignment(JLabel.CENTER)
            
        auth_header.setReorderingAllowed(False)
        auth_header.setPreferredSize(Dimension(auth_header.getPreferredSize().width, _S(30)))

        auth_cell_renderer = DefaultTableCellRenderer()
        auth_cell_renderer.setHorizontalAlignment(JLabel.CENTER)
        for col_index in range(self._auth_table.getColumnCount()):
            self._auth_table.getColumnModel().getColumn(col_index).setCellRenderer(auth_cell_renderer)

        type_combo = JComboBox(["Header", "Cookie", "URL", "Body"])
        type_combo.setBackground(self._c_field_bg)
        type_combo.setForeground(self._c_fg)
        type_editor = DefaultCellEditor(type_combo)
        self._auth_table.getColumnModel().getColumn(0).setCellEditor(type_editor)
        self._auth_table.getColumnModel().getColumn(0).setPreferredWidth(80)
        self._auth_table.getColumnModel().getColumn(0).setMaxWidth(120)

        edit_field = JTextField()
        edit_field.setHorizontalAlignment(JTextField.CENTER)
        edit_field.setBackground(self._c_field_bg)
        edit_field.setForeground(self._c_fg)
        edit_field.setCaretColor(self._c_fg)
        edit_field.setFont(Font("Monospaced", Font.BOLD, _S(8)))
        edit_field.setBorder(BorderFactory.createEmptyBorder(0, 4, 0, 4))
        
        centered_text_editor = DefaultCellEditor(edit_field)
        self._auth_table.getColumnModel().getColumn(1).setCellEditor(centered_text_editor)
        self._auth_table.getColumnModel().getColumn(2).setCellEditor(centered_text_editor)

        auth_scroll = JScrollPane(self._auth_table)
        auth_scroll.getViewport().setBackground(self._c_bg)
        auth_scroll.setBorder(BorderFactory.createLineBorder(self._c_grid, 1))

        auth_buttons = JPanel(FlowLayout(FlowLayout.LEFT, 8, 6))
        auth_buttons.setBackground(self._c_bg)
        auth_buttons.add(self._make_button("Add Row", "AUTH_ADD", accent=self._c_2xx))
        auth_buttons.add(self._make_button("Remove Row", "AUTH_REMOVE", accent=self._c_4xx))
        auth_buttons.add(self._make_button("Clear All", "AUTH_CLEAR"))

        auth_panel = JPanel(BorderLayout(0, 4))
        auth_panel.setBackground(self._c_bg)
        auth_panel.setBorder(self._section_border("Auth Material Injector"))
        auth_panel.add(top_auth_panel, BorderLayout.NORTH)
        auth_panel.add(auth_scroll, BorderLayout.CENTER)
        auth_panel.add(auth_buttons, BorderLayout.SOUTH)

        # -------------------------------------------------------------
        # REQUEST VIEWER SECTION
        # -------------------------------------------------------------

        self._request_status_label = JLabel("Request (original capture)")
        self._request_status_label.setForeground(self._c_fg_dim)
        self._request_status_label.setFont(Font("SansSerif", Font.BOLD | Font.ITALIC, _S(8)))
        self._request_status_label.setBorder(BorderFactory.createEmptyBorder(0, 2, 6, 0))

        self.requestViewer = self._callbacks.createMessageEditor(self, True)
        request_pane = JPanel(BorderLayout(0, 2))
        request_pane.setBackground(self._c_bg)
        request_pane.add(self._request_status_label, BorderLayout.NORTH)
        request_pane.add(self.requestViewer.getComponent(), BorderLayout.CENTER)

        self.responseViewer = self._callbacks.createMessageEditor(self, False)

        viewer_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, request_pane, self.responseViewer.getComponent())
        viewer_split.setResizeWeight(0.5)
        viewer_split.setDividerLocation(350)
        viewer_split.setBorder(None)
        viewer_split.setBackground(self._c_bg)
        viewer_split.setDividerSize(6)

        self._history_label = JLabel("History: 0 of 0 responses")
        self._history_label.setForeground(self._c_fg_dim)
        self._history_label.setFont(Font("SansSerif", Font.BOLD, _S(8)))

        viewer_nav = JPanel(FlowLayout(FlowLayout.LEFT, 8, 6))
        viewer_nav.setBackground(self._c_bg)
        viewer_nav.add(self._make_button("< Previous Response", "HIST_PREV"))
        viewer_nav.add(self._make_button("Next Response >", "HIST_NEXT"))
        viewer_nav.add(self._history_label)
        viewer_nav.add(self._make_button("Sync Edits to Queue", "SYNC_EDITS", accent=self._c_3xx))

        viewer_panel = JPanel(BorderLayout(0, 6))
        viewer_panel.setBackground(self._c_bg)
        viewer_panel.setBorder(self._section_border("Request / Response Viewer"))
        viewer_panel.add(viewer_split, BorderLayout.CENTER)
        viewer_panel.add(viewer_nav, BorderLayout.SOUTH)

        bottom_split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, auth_panel, viewer_panel)
        bottom_split.setResizeWeight(0.35)
        bottom_split.setBorder(None)
        bottom_split.setBackground(self._c_bg)
        bottom_split.setDividerSize(8)

        main_split = JSplitPane(JSplitPane.VERTICAL_SPLIT, queue_panel, bottom_split)
        main_split.setResizeWeight(0.6)
        main_split.setBorder(None)
        main_split.setBackground(self._c_bg)
        main_split.setDividerSize(8)

        self._main_panel.add(main_split, BorderLayout.CENTER)

        # Reload active profile data into the freshly created table models.
        # This is a no-op on first load (empty Default profile) and restores
        # all queued requests + auth entries when rebuilding after a scale change.
        self.refresh_queue_table()
        self.load_auth_profile_into_ui(self._active_auth_profile_name)
        self._selected_row = -1

    def _profile_order_array(self):
        return list(self._profile_order)

    def _auth_profile_order_array(self):
        return list(self._auth_profile_order)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # Capture when response is received to ensure prev_status exists
        if messageIsRequest: return
        if toolFlag != self._callbacks.TOOL_REPEATER: return
        if not self._capture_enabled: return

        try:
            http_service = messageInfo.getHttpService()
            request_bytes = messageInfo.getRequest()

            request_info = self._helpers.analyzeRequest(http_service, request_bytes)
            url = str(request_info.getUrl())
            method = request_info.getMethod()

            print("AuthzTester DEBUG: captured method=[%s]" % method)
            if method.upper() == "OPTIONS": return

            host = http_service.getHost()
            port = http_service.getPort()
            protocol = http_service.getProtocol()

            original_response = messageInfo.getResponse()
            self.log("Repeater capture: %s %s" % (method, url))
            self._ingest_and_add_row(request_bytes, host, port, protocol, url, method, original_response)
        except Exception as e:
            self.log("processHttpMessage error: %s" % str(e))

    def _ingest_and_add_row(self, request_bytes, host, port, protocol, url, method, original_response_bytes=None):
        result = self._build_captured_request(request_bytes, host, port, protocol, url, method, original_response_bytes)
        if result is None: return
        profile, captured = result

        def update_ui():
            if self._table_model.items is profile.requests:
                self._table_model.addItem(captured)
            else:
                self.refresh_queue_table()
        SwingUtilities.invokeLater(RunnableAdapter(update_ui))

    def _build_captured_request(self, request_bytes, host, port, protocol, url, method, original_response_bytes=None):
        with self._lock:
            profile = self._profiles.get(self._active_profile_name)
            if profile is None: return None

            digest = self._compute_dup_hash(request_bytes, method, url)
            dup_key = "%s::%s" % (profile.name, digest)
            if dup_key in self._dup_hashes: return None
            self._dup_hashes.add(dup_key)

            captured = CapturedRequest(request_bytes, host, port, protocol, url)
            captured.method = method
            captured.dup_key = dup_key
            captured.prev_status = ""
            captured.prev_size_bytes = ""
            if original_response_bytes:
                try: 
                    captured.prev_status = str(self._helpers.analyzeResponse(original_response_bytes).getStatusCode())
                    captured.prev_size_bytes = str(len(original_response_bytes))
                except: pass
            
            profile.requests.append(captured)
            return (profile, captured)

    def ingest_request(self, request_bytes, host, port, protocol, url=None, original_response_bytes=None):
        request_info = self._helpers.analyzeRequest(
            self._build_service(host, port, protocol), request_bytes
        )
        if url is None: url = str(request_info.getUrl())
        method = request_info.getMethod()
        result = self._build_captured_request(request_bytes, host, port, protocol, url, method, original_response_bytes)
        if result is not None:
            profile, captured = result
            if self._table_model.items is profile.requests:
                self._table_model.addItem(captured)

    def _build_service(self, host, port, protocol):
        return self._helpers.buildHttpService(host, port, protocol == "https")

    def _compute_dup_hash(self, request_bytes, method, url):
        raw = self._helpers.bytesToString(request_bytes)
        normalized = re.sub(r"HTTP/[12](\.[01])?", "HTTP/NORMALIZED", raw)
        digest_input = method + "|" + url + "|" + normalized
        return hashlib.md5(digest_input.encode("utf-8", "ignore")).hexdigest()

    def createMenuItems(self, invocation):
        factory = AuthZContextMenuFactory(self)
        return factory.createMenuItems(invocation)

    # ---------- Main Profile Handling ----------
    
    def on_profile_combo_changed(self):
        if self._switching_profile: return
        selected = self._profile_combo.getSelectedItem()
        if selected is None: return
        self._active_profile_name = str(selected)
        self.load_profile_into_ui(self._active_profile_name)

    def load_profile_into_ui(self, name):
        profile = self._profiles.get(name)
        if profile is None: return
        self.refresh_queue_table()
        self._clear_viewer()

    def refresh_profile_combo(self):
        self._switching_profile = True
        try:
            self._profile_combo.removeAllItems()
            for name in self._profile_order:
                self._profile_combo.addItem(name)
            self._profile_combo.setSelectedItem(self._active_profile_name)
        finally:
            self._switching_profile = False

    def refresh_queue_table(self):
        profile = self._profiles.get(self._active_profile_name)
        if profile is None:
            self._table_model.setItems([])
            return

        if self._table_model.items is profile.requests:
            self._table_model.fireTableDataChanged()
        else:
            self._table_model.setItems(profile.requests)

    # ---------- Auth Profile Handling ----------

    def on_auth_profile_combo_changed(self):
        if self._switching_auth_profile: return
        selected = self._auth_profile_combo.getSelectedItem()
        if selected is None: return
        self._save_current_auth_material()
        self._active_auth_profile_name = str(selected)
        self.load_auth_profile_into_ui(self._active_auth_profile_name)

    def _save_current_auth_material(self):
        if self._auth_table.isEditing():
            self._auth_table.getCellEditor().stopCellEditing()
        self._auth_profiles[self._active_auth_profile_name] = self._auth_table_model.getData()

    def load_auth_profile_into_ui(self, name):
        data = self._auth_profiles.get(name, [])
        self._auth_table_model.setData(data)

    def refresh_auth_profile_combo(self):
        self._switching_auth_profile = True
        try:
            self._auth_profile_combo.removeAllItems()
            for name in self._auth_profile_order:
                self._auth_profile_combo.addItem(name)
            self._auth_profile_combo.setSelectedItem(self._active_auth_profile_name)
        finally:
            self._switching_auth_profile = False


    # ---------- Viewer and History ----------

    def on_table_selection_changed(self):
        selected_row = self._table.getSelectedRow()
        if selected_row < 0: return
        model_row = self._table.convertRowIndexToModel(selected_row)
        self._selected_row = model_row
        self._load_request_into_viewer(model_row)

    def focus_request_viewer(self):
        self.requestViewer.getComponent().requestFocusInWindow()

    def show_queue_context_menu(self, event):
        row = self._table.rowAtPoint(event.getPoint())
        if row < 0: return
        if row not in self._table.getSelectedRows():
            self._table.setRowSelectionInterval(row, row)

        popup = JPopupMenu()
        repeater_item = JMenuItem("Send to Repeater")
        repeater_item.setActionCommand("SEND_TO_REPEATER")
        repeater_item.addActionListener(CommandDispatcher(self))
        popup.add(repeater_item)
        popup.show(event.getComponent(), event.getX(), event.getY())

    def _load_request_into_viewer(self, model_row):
        profile = self._profiles.get(self._active_profile_name)
        if profile is None or model_row >= len(profile.requests): return
        req = profile.requests[model_row]

        self._editor_http_service = self._build_service(req.host, req.port, req.protocol)

        if req.last_sent_bytes is not None:
            display_bytes = req.last_sent_bytes
            self._request_status_label.setText(
                "Request actually sent (auth material applied) -- editing here will NOT re-inject auth on next send"
            )
        else:
            display_bytes = req.request_bytes
            self._request_status_label.setText("Request (original capture, auth not yet sent)")
        self._editor_request_bytes = display_bytes
        self.requestViewer.setMessage(display_bytes, True)

        history = self._history_map.get(model_row, [])
        if history:
            pos = self._history_index.get(model_row, len(history) - 1)
            self._show_history_entry(model_row, pos)
        else:
            self._editor_response_bytes = None
            self.responseViewer.setMessage(EMPTY_BYTES, False)
            self._history_label.setText("History: 0 of 0 responses")

    def _clear_viewer(self):
        self._editor_http_service = None
        self._editor_request_bytes = None
        self._editor_response_bytes = None
        self.requestViewer.setMessage(EMPTY_BYTES, True)
        self.responseViewer.setMessage(EMPTY_BYTES, False)
        self._request_status_label.setText("Request (original capture)")
        self._history_label.setText("History: 0 of 0 responses")
        self._selected_row = -1

    def _show_history_entry(self, row_index, pos):
        history = self._history_map.get(row_index, [])
        if not history: return
        pos = max(0, min(pos, len(history) - 1))
        self._history_index[row_index] = pos
        entry = history[pos]
        if len(entry) == 5:
            status, time_ms, size_bytes, response_bytes, sent_request_bytes = entry
        else:
            status, time_ms, size_bytes, response_bytes = entry
            sent_request_bytes = None

        if sent_request_bytes is not None:
            self._editor_request_bytes = sent_request_bytes
            self.requestViewer.setMessage(sent_request_bytes, True)
            self._request_status_label.setText(
                "Request sent (history entry %d of %d, auth applied)" % (pos + 1, len(history))
            )

        self._editor_response_bytes = response_bytes
        if response_bytes is not None:
            self.responseViewer.setMessage(response_bytes, False)
        else:
            self.responseViewer.setMessage(EMPTY_BYTES, False)
        self._history_label.setText("History: %d of %d responses  (Status %s | %s ms | %s bytes)" % (
            pos + 1, len(history), status, time_ms, size_bytes
        ))

    def _parse_auth_data(self, auth_data):
        cookie_overrides = OrderedDict()
        other_headers = OrderedDict()
        url_params = OrderedDict()
        body_params = OrderedDict()
        raw_cookie_value = None  

        for row in auth_data:
            if len(row) == 3:
                a_type, a_name, a_val = row
            elif len(row) == 4:
                _, a_type, a_name, a_val = row
            else:
                continue
                
            a_type = str(a_type).strip() if a_type else ""
            a_name = str(a_name).strip() if a_name else ""
            a_val = str(a_val).strip() if a_val else ""

            if a_type == "Cookie" and not a_name:
                if a_val: raw_cookie_value = a_val
                continue

            if not a_name: continue

            if a_type == "Cookie": cookie_overrides[a_name] = a_val
            elif a_type == "Header": other_headers[a_name] = a_val
            elif a_type == "URL": url_params[a_name] = a_val
            elif a_type == "Body": body_params[a_name] = a_val

        return cookie_overrides, other_headers, url_params, body_params, raw_cookie_value

    def _merge_cookie_header_value(self, existing_value, cookie_overrides, raw_cookie_value=None):
        if raw_cookie_value is not None:
            extra = "; ".join(["%s=%s" % (k, v) for k, v in cookie_overrides.items()])
            return raw_cookie_value if not extra else raw_cookie_value + "; " + extra

        merged = OrderedDict()
        for pair in existing_value.split(";"):
            pair = pair.strip()
            if not pair or "=" not in pair: continue
            c_name, _, c_value = pair.partition("=")
            merged[c_name.strip()] = c_value.strip()
        for c_name, c_value in cookie_overrides.items():
            merged[c_name] = c_value
        return "; ".join(["%s=%s" % (k, v) for k, v in merged.items()])

    def _update_json_keys(self, obj, params):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in params: obj[k] = params[k]
                else: self._update_json_keys(v, params)
        elif isinstance(obj, list):
            for item in obj: self._update_json_keys(item, params)

    def _inject_auth(self, request_bytes, auth_data):
        cookie_overrides, other_headers, url_params, body_params, raw_cookie_value = \
            self._parse_auth_data(auth_data)

        if not cookie_overrides and not other_headers and not url_params \
                and not body_params and raw_cookie_value is None:
            return request_bytes

        request_info = self._helpers.analyzeRequest(request_bytes)
        existing_headers = list(request_info.getHeaders())
        body_offset = request_info.getBodyOffset()
        body_bytes = request_bytes[body_offset:]

        other_names_lower = set([n.lower() for n in other_headers.keys()])

        new_headers = ArrayList()
        new_headers.add(existing_headers[0])

        cookie_header_seen = False
        has_cookie_data = bool(cookie_overrides) or raw_cookie_value is not None

        for h in existing_headers[1:]:
            h_str = str(h)
            colon_idx = h_str.find(":")
            if colon_idx <= 0:
                new_headers.add(h)
                continue

            h_name = h_str[:colon_idx].strip()
            h_name_lower = h_name.lower()

            if h_name_lower == "cookie":
                cookie_header_seen = True
                if has_cookie_data:
                    existing_value = h_str[colon_idx + 1:].strip()
                    rebuilt = self._merge_cookie_header_value(
                        existing_value, cookie_overrides, raw_cookie_value)
                    new_headers.add("Cookie: %s" % rebuilt)
                else:
                    new_headers.add(h)
                continue

            if h_name_lower in other_names_lower: continue  
            new_headers.add(h)

        if not cookie_header_seen and has_cookie_data:
            if raw_cookie_value is not None:
                rebuilt = self._merge_cookie_header_value("", cookie_overrides, raw_cookie_value)
            else:
                rebuilt = "; ".join(["%s=%s" % (k, v) for k, v in cookie_overrides.items()])
            new_headers.add("Cookie: %s" % rebuilt)

        for name, value in other_headers.items():
            new_headers.add("%s: %s" % (name, value))

        modified_request = self._helpers.buildHttpMessage(new_headers, body_bytes)

        for name, value in url_params.items():
            param = self._helpers.buildParameter(name, value, 0)
            modified_request = self._helpers.removeParameter(modified_request, param)
            modified_request = self._helpers.addParameter(modified_request, param)

        if body_params:
            req_info = self._helpers.analyzeRequest(modified_request)
            headers = list(req_info.getHeaders())
            
            is_json = False
            for h in headers:
                if str(h).lower().startswith("content-type: application/json"):
                    is_json = True
                    break

            if is_json:
                try:
                    body_offset = req_info.getBodyOffset()
                    current_body_bytes = modified_request[body_offset:]
                    body_str = self._helpers.bytesToString(current_body_bytes)
                    
                    if body_str.strip():
                        json_data = json.loads(body_str, object_pairs_hook=OrderedDict)
                        self._update_json_keys(json_data, body_params)
                        new_body_str = json.dumps(json_data)
                        new_body_bytes = self._helpers.stringToBytes(new_body_str)
                        modified_request = self._helpers.buildHttpMessage(headers, new_body_bytes)
                except Exception as e:
                    self.log("Failed to inject JSON body params: %s" % str(e))
            else:
                for name, value in body_params.items():
                    param = self._helpers.buildParameter(name, value, 1)
                    modified_request = self._helpers.removeParameter(modified_request, param)
                    modified_request = self._helpers.addParameter(modified_request, param)

        return modified_request

    def _send_request_at_index(self, index):
        profile = self._profiles.get(self._active_profile_name)
        if profile is None or index >= len(profile.requests): return False
            
        req = profile.requests[index]
        
        if self._auth_table.isEditing():
            self._auth_table.getCellEditor().stopCellEditing()
        auth_data = self._auth_table_model.getData()

        try:
            modified_request = self._inject_auth(req.request_bytes, auth_data)
            req.last_sent_bytes = modified_request
            http_service = self._build_service(req.host, req.port, req.protocol)

            start_time = System.currentTimeMillis()
            response = self._callbacks.makeHttpRequest(http_service, modified_request)
            elapsed = System.currentTimeMillis() - start_time

            response_bytes = response.getResponse()
            if response_bytes is None:
                req.status = 0
                req.time_ms = int(elapsed)
                req.size_bytes = 0
                self._record_history(index, 0, int(elapsed), 0, None, modified_request)
                return False

            response_info = self._helpers.analyzeResponse(response_bytes)
            status_code = response_info.getStatusCode()
            size = len(response_bytes)

            req.status = status_code
            req.time_ms = int(elapsed)
            req.size_bytes = size
            req.response_bytes = response_bytes

            self._record_history(index, status_code, int(elapsed), size, response_bytes, modified_request)
            return True
        except Exception as e:
            self.log("Send error (index %d): %s" % (index, str(e)))
            req.status = "error"
            req.time_ms = None
            req.size_bytes = None
            return False

    def _record_history(self, index, status, time_ms, size, response_bytes, sent_request_bytes=None):
        entry = (status, time_ms, size, response_bytes, sent_request_bytes)
        if index not in self._history_map:
            self._history_map[index] = []
        self._history_map[index].append(entry)
        self._history_index[index] = len(self._history_map[index]) - 1

    def handle_action(self, command):
        try:
            if command == "TOGGLE_CAPTURE": self._capture_enabled = self._capture_checkbox.isSelected()
            elif command == "NEW_PROFILE": self._action_new_profile()
            elif command == "RENAME_PROFILE": self._action_rename_profile()
            elif command == "DELETE_PROFILE": self._action_delete_profile()
            
            elif command == "NEW_AUTH_PROFILE": self._action_new_auth_profile()
            elif command == "RENAME_AUTH_PROFILE": self._action_rename_auth_profile()
            elif command == "DELETE_AUTH_PROFILE": self._action_delete_auth_profile()
            
            elif command == "CLEAR_QUEUE": self._action_clear_queue()
            elif command == "SEND_ALL": self._action_send_all()
            elif command == "SEND_SELECTED": self._action_send_selected()
            elif command == "RESUME_SENDING": self._action_resume_sending()
            elif command == "STOP_SENDING": self._action_stop_sending()
            elif command == "REMOVE_SELECTED": self._action_remove_selected()
            elif command == "EXPORT_STATE": self._action_export_state()
            elif command == "IMPORT_STATE": self._action_import_state()
            elif command == "AUTH_ADD": self._auth_table_model.addRow()
            elif command == "AUTH_REMOVE": self._action_auth_remove()
            elif command == "AUTH_CLEAR": self._auth_table_model.clear()
            elif command == "HIST_PREV": self._action_history_prev()
            elif command == "HIST_NEXT": self._action_history_next()
            elif command == "SYNC_EDITS": self._action_sync_edits()
            elif command == "SEND_TO_REPEATER": self._action_send_to_repeater()
        except Exception as e:
            self.log("handle_action error [%s]: %s" % (command, str(e)))

    # -------- Main Profile Actions --------

    def _action_new_profile(self):
        name = JOptionPane.showInputDialog(self._main_panel, "New profile name:")
        if name is None: return
        name = name.strip()
        if not name:
            JOptionPane.showMessageDialog(self._main_panel, "Profile name cannot be empty.")
            return
        if name in self._profiles:
            JOptionPane.showMessageDialog(self._main_panel, "A profile with that name already exists.")
            return
        self._profiles[name] = UserProfile(name)
        self._profile_order.append(name)
        self._active_profile_name = name
        self.refresh_profile_combo()
        self.load_profile_into_ui(name)

    def _action_rename_profile(self):
        old_name = self._active_profile_name
        if old_name == "Default":
            JOptionPane.showMessageDialog(self._main_panel, "The Default profile cannot be renamed.")
            return
        new_name = JOptionPane.showInputDialog(self._main_panel, "Rename profile '%s' to:" % old_name)
        if new_name is None: return
        new_name = new_name.strip()
        if not new_name or new_name in self._profiles:
            JOptionPane.showMessageDialog(self._main_panel, "Invalid or duplicate profile name.")
            return
        profile = self._profiles.pop(old_name)
        profile.name = new_name
        self._profiles[new_name] = profile
        idx = self._profile_order.index(old_name)
        self._profile_order[idx] = new_name
        self._active_profile_name = new_name
        self.refresh_profile_combo()

    def _action_delete_profile(self):
        name = self._active_profile_name
        if name == "Default":
            JOptionPane.showMessageDialog(self._main_panel, "The Default profile cannot be deleted.")
            return
        confirm = JOptionPane.showConfirmDialog(
            self._main_panel,
            "Delete profile '%s' and all its captured requests?" % name,
            "Confirm Delete",
            JOptionPane.YES_NO_OPTION
        )
        if confirm != JOptionPane.YES_OPTION: return
        del self._profiles[name]
        self._profile_order.remove(name)
        self._active_profile_name = "Default"
        self.refresh_profile_combo()
        self.load_profile_into_ui("Default")

    # -------- Auth Profile Actions --------

    def _action_new_auth_profile(self):
        name = JOptionPane.showInputDialog(self._main_panel, "New Auth Profile name:")
        if name is None: return
        name = name.strip()
        if not name:
            JOptionPane.showMessageDialog(self._main_panel, "Auth Profile name cannot be empty.")
            return
        if name in self._auth_profiles:
            JOptionPane.showMessageDialog(self._main_panel, "An Auth Profile with that name already exists.")
            return
        self._save_current_auth_material()
        self._auth_profiles[name] = []
        self._auth_profile_order.append(name)
        self._active_auth_profile_name = name
        self.refresh_auth_profile_combo()
        self.load_auth_profile_into_ui(name)

    def _action_rename_auth_profile(self):
        old_name = self._active_auth_profile_name
        if old_name == "Default":
            JOptionPane.showMessageDialog(self._main_panel, "The Default Auth Profile cannot be renamed.")
            return
        new_name = JOptionPane.showInputDialog(self._main_panel, "Rename Auth Profile '%s' to:" % old_name)
        if new_name is None: return
        new_name = new_name.strip()
        if not new_name or new_name in self._auth_profiles:
            JOptionPane.showMessageDialog(self._main_panel, "Invalid or duplicate auth profile name.")
            return
        self._save_current_auth_material()
        data = self._auth_profiles.pop(old_name)
        self._auth_profiles[new_name] = data
        idx = self._auth_profile_order.index(old_name)
        self._auth_profile_order[idx] = new_name
        self._active_auth_profile_name = new_name
        self.refresh_auth_profile_combo()

    def _action_delete_auth_profile(self):
        name = self._active_auth_profile_name
        if name == "Default":
            JOptionPane.showMessageDialog(self._main_panel, "The Default Auth Profile cannot be deleted.")
            return
        confirm = JOptionPane.showConfirmDialog(
            self._main_panel,
            "Delete Auth Profile '%s'?" % name,
            "Confirm Delete",
            JOptionPane.YES_NO_OPTION
        )
        if confirm != JOptionPane.YES_OPTION: return
        del self._auth_profiles[name]
        self._auth_profile_order.remove(name)
        self._active_auth_profile_name = "Default"
        self.refresh_auth_profile_combo()
        self.load_auth_profile_into_ui("Default")


    def _action_clear_queue(self):
        confirm = JOptionPane.showConfirmDialog(
            self._main_panel,
            "Clear all queued requests for profile '%s'?" % self._active_profile_name,
            "Confirm Clear",
            JOptionPane.YES_NO_OPTION
        )
        if confirm != JOptionPane.YES_OPTION: return
        with self._lock:
            profile = self._profiles.get(self._active_profile_name)
            if profile is not None:
                profile.requests = []
            prefix = "%s::" % self._active_profile_name
            self._dup_hashes = set([h for h in self._dup_hashes if not h.startswith(prefix)])
        self._history_map = {}
        self._history_index = {}
        self.refresh_queue_table()
        self._clear_viewer()

    def _action_send_all(self):
        profile = self._profiles.get(self._active_profile_name)
        if profile is None or not profile.requests:
            JOptionPane.showMessageDialog(self._main_panel, "No requests in queue.")
            return
            
        indices = list(range(len(profile.requests)))
        self._current_run_id += 1 
        self._set_send_buttons_enabled(False)
        
        worker = threading.Thread(
            target=self._send_worker,
            args=(indices, self._current_run_id)
        )
        worker.setDaemon(True)
        worker.start()

    def _action_send_selected(self):
        selected_rows = self._table.getSelectedRows()
        if not selected_rows:
            JOptionPane.showMessageDialog(self._main_panel, "No rows selected.")
            return
            
        model_indices = sorted([self._table.convertRowIndexToModel(r) for r in selected_rows])
        self._current_run_id += 1 
        self._set_send_buttons_enabled(False)
        
        worker = threading.Thread(
            target=self._send_worker,
            args=(model_indices, self._current_run_id)
        )
        worker.setDaemon(True)
        worker.start()
        
    def _action_resume_sending(self):
        profile = self._profiles.get(self._active_profile_name)
        if profile is None or not profile.requests:
            JOptionPane.showMessageDialog(self._main_panel, "No requests to resume.")
            return
            
        indices = []
        for i, req in enumerate(profile.requests):
            if req.status is None or req.status == "error" or req.status == "sending...":
                indices.append(i)
                
        if not indices:
            JOptionPane.showMessageDialog(self._main_panel, "All requests have already been sent.")
            return
            
        self._current_run_id += 1 
        self._set_send_buttons_enabled(False)
        
        worker = threading.Thread(
            target=self._send_worker,
            args=(indices, self._current_run_id)
        )
        worker.setDaemon(True)
        worker.start()

    def _action_stop_sending(self):
        self._current_run_id += 1 
        self._set_send_buttons_enabled(True)
        self.log("User aborted the active send queue.")

    def _set_send_buttons_enabled(self, enabled):
        def _toggle():
            self._send_all_button.setEnabled(enabled)
            self._send_selected_button.setEnabled(enabled)
            self._resume_button.setEnabled(enabled)
            self._stop_button.setEnabled(not enabled)
        SwingUtilities.invokeLater(RunnableAdapter(_toggle))

    def _send_worker(self, indices, run_id):
        profile = self._profiles.get(self._active_profile_name)
        if profile is None:
            if self._current_run_id == run_id:
                self._set_send_buttons_enabled(True)
            return

        for index in indices:
            if self._current_run_id != run_id: break
            if not (0 <= index < len(profile.requests)): continue
                
            req = profile.requests[index]
            req.status = "sending..."
            req.time_ms = None
            req.size_bytes = None
            captured_index = index

            def _mark_sending(idx=captured_index):
                if idx < self._table_model.getRowCount():
                    self._table_model.fireRowUpdated(idx)
            SwingUtilities.invokeLater(RunnableAdapter(_mark_sending))

            self._send_request_at_index(index)

            def _update_row(idx=captured_index):
                if idx < self._table_model.getRowCount():
                    self._table_model.fireRowUpdated(idx)
                    if self._selected_row == idx:
                        self._load_request_into_viewer(idx)
            SwingUtilities.invokeLater(RunnableAdapter(_update_row))

        def _finish():
            if self._current_run_id == run_id:
                self._set_send_buttons_enabled(True)
        SwingUtilities.invokeLater(RunnableAdapter(_finish))

    def _action_send_to_repeater(self):
        selected_rows = self._table.getSelectedRows()
        if not selected_rows: return
        profile = self._profiles.get(self._active_profile_name)
        if profile is None: return
        model_indices = sorted([self._table.convertRowIndexToModel(r) for r in selected_rows])
        for idx in model_indices:
            if not (0 <= idx < len(profile.requests)): continue
            req = profile.requests[idx]
            request_bytes = req.last_sent_bytes if req.last_sent_bytes is not None else req.request_bytes
            use_https = (req.protocol == "https")
            tab_caption = "AuthZ %d" % idx
            try:
                self._callbacks.sendToRepeater(req.host, req.port, use_https, request_bytes, tab_caption)
            except Exception as e:
                self.log("sendToRepeater error (index %d): %s" % (idx, str(e)))

    def _action_remove_selected(self):
        selected_rows = self._table.getSelectedRows()
        if not selected_rows: return
        model_indices = sorted(
            [self._table.convertRowIndexToModel(r) for r in selected_rows],
            reverse=True
        )
        profile = self._profiles.get(self._active_profile_name)
        if profile is None: return
        with self._lock:
            for idx in model_indices:
                if 0 <= idx < len(profile.requests):
                    req = profile.requests[idx]
                    if hasattr(req, 'dup_key') and req.dup_key and req.dup_key in self._dup_hashes:
                        self._dup_hashes.remove(req.dup_key)
                    del profile.requests[idx]
                if idx in self._history_map:
                    del self._history_map[idx]
                if idx in self._history_index:
                    del self._history_index[idx]
        self.refresh_queue_table()
        self._clear_viewer()


    def _action_export_state(self):
        self._save_current_auth_material()
        
        profile = self._profiles.get(self._active_profile_name)
        if profile is None:
            return

        chooser = JFileChooser()
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        safe_prof = re.sub(r'[^a-zA-Z0-9_\-]', '_', profile.name)
        chooser.setSelectedFile(java.io.File("authz_tester_%s_%s.json" % (safe_prof, timestamp)))
        result = chooser.showSaveDialog(self._main_panel)
        if result != JFileChooser.APPROVE_OPTION: return
        path = chooser.getSelectedFile().getAbsolutePath()
        if not path.lower().endswith(".json"):
            path += ".json"

        try:
            requests_out = []
            for idx, req in enumerate(profile.requests):
                history_entries = self._history_map.get(idx, [])
                history_out = []
                for entry in history_entries:
                    if len(entry) == 5:
                        st, tms, sz, resp_b, sent_b = entry
                    else:
                        st, tms, sz, resp_b = entry
                        sent_b = None
                    history_out.append({
                        "status": st,
                        "time_ms": tms,
                        "size_bytes": sz,
                        "response_bytes": self._b64(resp_b),
                        "sent_request_bytes": self._b64(sent_b)
                    })
                
                requests_out.append({
                    "host": req.host,
                    "port": req.port,
                    "protocol": req.protocol,
                    "url": req.url,
                    "method": req.method,
                    "request_bytes": self._b64(req.request_bytes),
                    "response_bytes": self._b64(req.response_bytes),
                    "last_sent_bytes": self._b64(req.last_sent_bytes),
                    "prev_status": req.prev_status,
                    "prev_size_bytes": req.prev_size_bytes,
                    "status": req.status,
                    "time_ms": req.time_ms,
                    "size_bytes": req.size_bytes,
                    "history": history_out,
                    "history_index": self._history_index.get(idx, len(history_out)-1)
                })

            auth_profiles_out = []
            for name in self._auth_profile_order:
                auth_profiles_out.append({
                    "name": name,
                    "auth_material": self._auth_profiles[name]
                })

            with open(path, "w") as f:
                json.dump({
                    "tool": "AuthzTester", "version": 3,
                    "active_profile": self._active_profile_name,
                    "active_auth_profile": self._active_auth_profile_name,
                    "profile": profile.name,
                    "requests": requests_out,
                    "auth_profiles": auth_profiles_out
                }, f, indent=2)

            JOptionPane.showMessageDialog(
                self._main_panel,
                "Exported profile '%s' to:\n%s" % (profile.name, path))
        except Exception as e:
            self.log("Export state error: %s" % str(e))
            JOptionPane.showMessageDialog(self._main_panel, "Export failed: %s" % str(e))

    def _action_import_state(self):
        chooser = JFileChooser()
        result = chooser.showOpenDialog(self._main_panel)
        if result != JFileChooser.APPROVE_OPTION: return
        path = chooser.getSelectedFile().getAbsolutePath()

        try:
            with open(path, "r") as f:
                data = json.load(f)

            if "auth_profiles" in data:
                for ap in data.get("auth_profiles", []):
                    name = ap.get("name", "ImportedAuth")
                    if name not in self._auth_profiles:
                        self._auth_profiles[name] = ap.get("auth_material", [])
                        self._auth_profile_order.append(name)
                    else:
                        self._auth_profiles[name] = ap.get("auth_material", [])
                
                self._active_auth_profile_name = data.get("active_auth_profile", "Default")
                if self._active_auth_profile_name not in self._auth_profiles:
                    if self._auth_profile_order:
                        self._active_auth_profile_name = self._auth_profile_order[0]
                    else:
                        self._active_auth_profile_name = "Default"
                        self._auth_profiles["Default"] = []
                        self._auth_profile_order.append("Default")

                self.refresh_auth_profile_combo()
                self.load_auth_profile_into_ui(self._active_auth_profile_name)

            else:
                legacy_auth_loaded = False
                for p_entry in data.get("profiles", []):
                    if p_entry.get("auth_material"):
                        name = p_entry.get("name", "Imported")
                        auth_name = name + "_Auth"
                        if auth_name not in self._auth_profiles:
                            self._auth_profiles[auth_name] = p_entry["auth_material"]
                            self._auth_profile_order.append(auth_name)
                        legacy_auth_loaded = True
                        self._active_auth_profile_name = auth_name
                
                if legacy_auth_loaded:
                    self.refresh_auth_profile_combo()
                    self.load_auth_profile_into_ui(self._active_auth_profile_name)


            profile_name = data.get("profile")
            
            if profile_name is None and "profiles" in data:
                imported_profiles = 0
                imported_requests = 0
                for p_entry in data.get("profiles", []):
                    name = p_entry.get("name", "Imported")
                    if name not in self._profiles:
                        self._profiles[name] = UserProfile(name)
                        self._profile_order.append(name)
                    profile = self._profiles[name]

                    start_idx = len(profile.requests)
                    for i, r_entry in enumerate(p_entry.get("requests", [])):
                        captured = CapturedRequest(
                            self._unb64(r_entry.get("request_bytes")),
                            str(r_entry.get("host", "")),
                            int(r_entry.get("port", 443)),
                            str(r_entry.get("protocol", "https")),
                            r_entry.get("url", ""))
                        captured.method = r_entry.get("method", "GET")
                        captured.prev_status = r_entry.get("prev_status", "")
                        captured.prev_size_bytes = r_entry.get("prev_size_bytes", "")
                        captured.status = r_entry.get("status")
                        captured.time_ms = r_entry.get("time_ms")
                        captured.size_bytes = r_entry.get("size_bytes")
                        captured.response_bytes = self._unb64(r_entry.get("response_bytes"))
                        captured.last_sent_bytes = self._unb64(r_entry.get("last_sent_bytes"))
                        
                        digest = self._compute_dup_hash(captured.request_bytes, captured.method, captured.url)
                        dup_key = "%s::%s" % (profile.name, digest)
                        captured.dup_key = dup_key
                        self._dup_hashes.add(dup_key)

                        profile.requests.append(captured)
                        imported_requests += 1
                    imported_profiles += 1

                self.refresh_profile_combo()
                self.load_profile_into_ui(self._active_profile_name)

                JOptionPane.showMessageDialog(
                    self._main_panel,
                    "Imported %d profile(s), %d request(s) (Legacy format)." % (imported_profiles, imported_requests))
                return

            if not profile_name:
                profile_name = "Imported"

            if profile_name not in self._profiles:
                self._profiles[profile_name] = UserProfile(profile_name)
                self._profile_order.append(profile_name)
            
            self._active_profile_name = profile_name
            profile = self._profiles[profile_name]

            imported_requests = 0
            start_idx = len(profile.requests)
            
            for i, r_entry in enumerate(data.get("requests", [])):
                captured = CapturedRequest(
                    self._unb64(r_entry.get("request_bytes")),
                    str(r_entry.get("host", "")),
                    int(r_entry.get("port", 443)),
                    str(r_entry.get("protocol", "https")),
                    r_entry.get("url", ""))
                captured.method = r_entry.get("method", "GET")
                captured.prev_status = r_entry.get("prev_status", "")
                captured.prev_size_bytes = r_entry.get("prev_size_bytes", "")
                captured.status = r_entry.get("status")
                captured.time_ms = r_entry.get("time_ms")
                captured.size_bytes = r_entry.get("size_bytes")
                captured.response_bytes = self._unb64(r_entry.get("response_bytes"))
                captured.last_sent_bytes = self._unb64(r_entry.get("last_sent_bytes"))
                
                digest = self._compute_dup_hash(captured.request_bytes, captured.method, captured.url)
                dup_key = "%s::%s" % (profile.name, digest)
                captured.dup_key = dup_key
                self._dup_hashes.add(dup_key)

                profile.requests.append(captured)
                
                new_idx = start_idx + i
                history_in = r_entry.get("history", [])
                if history_in:
                    self._history_map[new_idx] = []
                    for h in history_in:
                        st = h.get("status")
                        tms = h.get("time_ms")
                        sz = h.get("size_bytes")
                        resp_b = self._unb64(h.get("response_bytes"))
                        sent_b = self._unb64(h.get("sent_request_bytes"))
                        self._history_map[new_idx].append((st, tms, sz, resp_b, sent_b))
                    self._history_index[new_idx] = r_entry.get("history_index", len(history_in)-1)
                    
                imported_requests += 1

            self.refresh_profile_combo()
            self.load_profile_into_ui(self._active_profile_name)

            JOptionPane.showMessageDialog(
                self._main_panel,
                "Imported profile '%s' with %d request(s)." % (profile_name, imported_requests))
        except Exception as e:
            self.log("Import state error: %s" % str(e))
            JOptionPane.showMessageDialog(self._main_panel, "Import failed: %s" % str(e))

    def _b64(self, raw_bytes):
        if raw_bytes is None: return None
        raw_str = "".join([chr(b & 0xFF) for b in raw_bytes])
        return base64.b64encode(raw_str)

    def _unb64(self, b64_str):
        if not b64_str: return None
        decoded = base64.b64decode(str(b64_str))
        return self._helpers.stringToBytes(decoded)

    def _open_with_default_app(self, path):
        try:
            if os.name == "nt": os.startfile(path)
            else:
                import subprocess
                try: subprocess.Popen(["xdg-open", path])
                except Exception: subprocess.Popen(["open", path])
        except Exception as e:
            self.log("Could not auto-open exported file: %s" % str(e))

    def _action_auth_remove(self):
        selected_rows = self._auth_table.getSelectedRows()
        if not selected_rows: return
        
        if self._auth_table.isEditing():
            self._auth_table.getCellEditor().stopCellEditing()
            
        model_indices = sorted(
            [self._auth_table.convertRowIndexToModel(r) for r in selected_rows],
            reverse=True
        )
        for idx in model_indices:
            self._auth_table_model.removeRow(idx)

    def _action_history_prev(self):
        if self._selected_row < 0: return
        pos = self._history_index.get(self._selected_row, 0)
        self._show_history_entry(self._selected_row, pos - 1)

    def _action_history_next(self):
        if self._selected_row < 0: return
        pos = self._history_index.get(self._selected_row, 0)
        self._show_history_entry(self._selected_row, pos + 1)

    def _action_sync_edits(self):
        if self._selected_row < 0:
            JOptionPane.showMessageDialog(self._main_panel, "No request selected.")
            return
        profile = self._profiles.get(self._active_profile_name)
        if profile is None or self._selected_row >= len(profile.requests): return
        new_bytes = self.requestViewer.getMessage()

        req = profile.requests[self._selected_row]
        req.request_bytes = new_bytes
        req.last_sent_bytes = None  
        try:
            request_info = self._helpers.analyzeRequest(
                self._build_service(req.host, req.port, req.protocol), new_bytes
            )
            req.method = request_info.getMethod()
            req.url = str(request_info.getUrl())
        except Exception as e:
            self.log("Sync edits analyze error: %s" % str(e))

        self.refresh_queue_table()
        self._request_status_label.setText("Request (original capture, auth not yet sent)")
        JOptionPane.showMessageDialog(self._main_panel, "Edits synced to queue.")


class RunnableAdapter(Runnable):
    def __init__(self, fn): self._fn = fn
    def run(self): self._fn()


# ===========================================================================
# Outer extension: Repeater2
# ===========================================================================


# ===========================================================================
# ScaleBar — top-level UI scale control (shared across all sub-tabs)
# ===========================================================================

class ScaleBar(JPanel):
    """
    A thin toolbar that lives at the very top of the Repeater2 suite tab.
    It shows the current scale factor and lets the user pick a different one.
    Changing the scale rebuilds all three sub-tab UIs on the EDT so every
    button, font, and row height immediately reflects the new size.
    """

    def __init__(self, extender_ref):
        JPanel.__init__(self, FlowLayout(FlowLayout.LEFT, 8, 4))
        self._ext = extender_ref
        self.setBackground(BG_HEADER)

        lbl = JLabel("UI Scale:")
        lbl.setForeground(TEXT_MUTED)
        lbl.setFont(Font("SansSerif", Font.BOLD, 11))
        self.add(lbl)

        # Build combo items
        self._combo = JComboBox([label for label, _ in SCALE_PRESETS])
        self._combo.setBackground(BG_PANEL)
        self._combo.setForeground(TEXT_LIGHT)
        self._combo.setFont(Font("SansSerif", Font.BOLD, 11))
        self._combo.setToolTipText("Resize all buttons, fonts and rows - independent of Burp zoom")

        # Pre-select the entry closest to the auto-detected DPI scale
        current = _SCALE()
        best_idx = 0
        best_dist = 999.0
        for i, (_, v) in enumerate(SCALE_PRESETS):
            d = abs(v - current)
            if d < best_dist:
                best_dist = d
                best_idx = i
        self._combo.setSelectedIndex(best_idx)
        # Apply so _SCALE_BOX matches the snapped preset value
        set_scale(SCALE_PRESETS[best_idx][1])

        _combo_ref = self._combo
        _ext_ref   = self._ext

        class _ScaleListener(ActionListener):
            def actionPerformed(self2, e):
                idx = _combo_ref.getSelectedIndex()
                if 0 <= idx < len(SCALE_PRESETS):
                    set_scale(SCALE_PRESETS[idx][1])
                    _ext_ref.rebuild_sub_tabs()

        self._combo.addActionListener(_ScaleListener())
        self.add(self._combo)

        hint = JLabel("(rebuilds UI - Burp zoom unchanged)")
        hint.setForeground(TEXT_MUTED)
        hint.setFont(Font("SansSerif", Font.ITALIC, 10))
        self.add(hint)

class BurpExtender(IBurpExtender, ITab, IHttpListener, IContextMenuFactory,
                    IMessageEditorController):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Repeater2 By Faizan Kurawle")

        self.noAuth = NoAuthExtender()
        self.noAuth.init(callbacks)

        self.jwtAttacker = JWTAttackerExtender()
        self.jwtAttacker.init(callbacks)

        self.authzTester = AuthZTesterExtender()
        self.authzTester.init(callbacks)

        self.tabs = JTabbedPane()
        self.tabs.addTab("NoAuth", self.noAuth.getUiComponent())
        self.tabs.addTab("JWT Attacker", self.jwtAttacker.getUiComponent())
        self.tabs.addTab("AuthzTester", self.authzTester.getUiComponent())
        self.tabs.setBackground(BG_PANEL)
        self.tabs.setForeground(TEXT_LIGHT)

        self._scale_bar = ScaleBar(self)

        self._panel = JPanel(BorderLayout())
        self._panel.setBackground(BG_PANEL)
        self._panel.add(self._scale_bar, BorderLayout.NORTH)
        self._panel.add(self.tabs, BorderLayout.CENTER)

        # Wire count callbacks so each extender fires tab title updates
        self.noAuth._count_cb      = self.update_tab_counts
        self.jwtAttacker._count_cb = self.update_tab_counts
        self.authzTester._count_cb = self.update_tab_counts
        self.update_tab_counts()

        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

        print("Repeater2 loaded: NoAuth + JWT Attacker + AuthzTester.")

    def rebuild_sub_tabs(self):
        """
        Rebuild all three sub-tab UIs after a scale change.
        Calls rebuild_ui() on each extender — state is fully preserved.
        Runs on the EDT; remembers which tab was active.
        """
        _self = self

        class _Rebuilder(Runnable):
            def run(self2):
                active = _self.tabs.getSelectedIndex()

                _self.noAuth.rebuild_ui()
                _self.jwtAttacker.rebuild_ui()
                _self.authzTester.rebuild_ui()

                _self.tabs.removeAll()
                _self.tabs.addTab("NoAuth", _self.noAuth.getUiComponent())
                _self.tabs.addTab("JWT Attacker", _self.jwtAttacker.getUiComponent())
                _self.tabs.addTab("AuthzTester", _self.authzTester.getUiComponent())
                _self.tabs.setBackground(BG_PANEL)
                _self.tabs.setForeground(TEXT_LIGHT)

                if 0 <= active < _self.tabs.getTabCount():
                    _self.tabs.setSelectedIndex(active)

                # Re-wire count callbacks after panels are rebuilt
                _self.noAuth._count_cb      = _self.update_tab_counts
                _self.jwtAttacker._count_cb = _self.update_tab_counts
                _self.authzTester._count_cb = _self.update_tab_counts
                _self.update_tab_counts()

                _self._panel.revalidate()
                _self._panel.repaint()

        SwingUtilities.invokeLater(_Rebuilder())

    def update_tab_counts(self):
        """Update the outer tab titles to show live request counts."""
        def _do_update():
            try:
                na_n  = self.noAuth.get_request_count()
                jwt_n = self.jwtAttacker.get_request_count()
                az_n  = self.authzTester.get_request_count()
                self.tabs.setTitleAt(0, "NoAuth (%d)" % na_n)
                self.tabs.setTitleAt(1, "JWT Attacker (%d)" % jwt_n)
                self.tabs.setTitleAt(2, "AuthzTester (%d)" % az_n)
            except Exception:
                pass
        SwingUtilities.invokeLater(RunnableAdapter(_do_update))

    def getTabCaption(self): return "Repeater2 By Faizan Kurawle"
    def getUiComponent(self): return self._panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        self.noAuth.processHttpMessage(toolFlag, messageIsRequest, messageInfo)
        self.jwtAttacker.processHttpMessage(toolFlag, messageIsRequest, messageInfo)
        self.authzTester.processHttpMessage(toolFlag, messageIsRequest, messageInfo)

    def createMenuItems(self, invocation):
        factory = CombinedContextMenuFactory(self.noAuth, self.jwtAttacker, self.authzTester)
        return factory.createMenuItems(invocation)

    def _active_controller(self):
        idx = self.tabs.getSelectedIndex()
        if idx == 0: return self.noAuth
        if idx == 2: return self.authzTester
        return None

    def getHttpService(self):
        ctl = self._active_controller()
        return ctl.getHttpService() if ctl else None

    def getRequest(self):
        ctl = self._active_controller()
        return ctl.getRequest() if ctl else None

    def getResponse(self):
        ctl = self._active_controller()
        return ctl.getResponse() if ctl else None