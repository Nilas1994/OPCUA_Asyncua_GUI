#!/usr/bin/env python3
"""
Dark mode styling for OPC UA Client
"""
from PyQt5.QtGui import QPalette, QColor
from PyQt5.QtCore import Qt


def apply_dark_style(app):
    """Apply dark mode style to application
    
    Args:
        app: QApplication instance
    """
    # Create dark palette
    palette = QPalette()
    
    # Base colors
    dark_color = QColor(45, 45, 45)
    disabled_color = QColor(70, 70, 70)
    text_color = QColor(220, 220, 220)
    highlight_color = QColor(42, 130, 218)
    highlight_text_color = Qt.white
    
    # Set base colors for the palette
    palette.setColor(QPalette.Window, dark_color)
    palette.setColor(QPalette.WindowText, text_color)
    palette.setColor(QPalette.Base, QColor(25, 25, 25))
    palette.setColor(QPalette.AlternateBase, dark_color)
    palette.setColor(QPalette.ToolTipBase, dark_color)
    palette.setColor(QPalette.ToolTipText, text_color)
    palette.setColor(QPalette.Text, text_color)
    palette.setColor(QPalette.Disabled, QPalette.Text, QColor(120, 120, 120))
    palette.setColor(QPalette.Button, dark_color)
    palette.setColor(QPalette.ButtonText, text_color)
    palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(120, 120, 120))
    palette.setColor(QPalette.BrightText, Qt.red)
    palette.setColor(QPalette.Link, QColor(42, 130, 218))
    palette.setColor(QPalette.Highlight, highlight_color)
    palette.setColor(QPalette.HighlightedText, highlight_text_color)
    palette.setColor(QPalette.Disabled, QPalette.HighlightedText, QColor(120, 120, 120))
    
    # Apply palette to application
    app.setPalette(palette)
    
    # Set stylesheet for additional customization
    app.setStyleSheet("""
        QToolTip { 
            color: #ffffff; 
            background-color: #2a82da; 
            border: 1px solid white; 
        }
        
        QWidget {
            background-color: #2d2d2d;
            color: #dedede;
        }
        
        QTabWidget::pane {
            border: 1px solid #444;
            top: -1px;
        }
        
        QTabBar::tab {
            background: #2d2d2d;
            border: 1px solid #444;
            padding: 6px 10px;
            margin-right: 1px;
        }
        
        QTabBar::tab:selected {
            background: #3d3d3d;
        }
        
        QTabBar::tab:!selected {
            background: #1d1d1d;
        }
        
        QTabBar::tab:!selected:hover {
            background: #3a3a3a;
        }
        
        QHeaderView::section {
            background-color: #3a3a3a;
            padding: 4px;
            border: 1px solid #444;
        }
        
        QTableView {
            gridline-color: #444;
            background-color: #191919;
            selection-background-color: #2a82da;
            selection-color: #ffffff;
        }
        
        QTableView::item:hover {
            background-color: #333333;
        }
        
        QTreeView {
            background-color: #191919;
            selection-background-color: #2a82da;
            selection-color: #ffffff;
        }
        
        QTreeView::item:hover {
            background-color: #333333;
        }
        
        QTreeView::item:selected {
            background-color: #2a82da;
        }
        
        QLineEdit, QTextEdit, QPlainTextEdit, QSpinBox, QDoubleSpinBox, QComboBox, QDateEdit, QTimeEdit, QDateTimeEdit {
            border: 1px solid #444;
            background-color: #191919;
            selection-background-color: #2a82da;
            selection-color: #ffffff;
        }
        
        QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus {
            border: 1px solid #2a82da;
        }
        
        QProgressBar {
            border: 1px solid #444;
            background-color: #191919;
            text-align: center;
        }
        
        QProgressBar::chunk {
            background-color: #2a82da;
        }
        
        QStatusBar {
            background-color: #3a3a3a;
            border-top: 1px solid #444;
        }
        
        QLabel[connectionStatus="connected"] {
            color: #00cc00;
        }
        
        QLabel[connectionStatus="disconnected"] {
            color: #cc0000;
        }
        
        QLabel[connectionStatus="connecting"] {
            color: #cccc00;
        }
        
        QLabel[connectionStatus="error"] {
            color: #ff6600;
        }
        
        QCheckBox::indicator:unchecked {
            image: url(:/icons/checkbox_unchecked.png);
        }
        
        QCheckBox::indicator:checked {
            image: url(:/icons/checkbox_checked.png);
        }
        
        QRadioButton::indicator:unchecked {
            image: url(:/icons/radiobutton_unchecked.png);
        }
        
        QRadioButton::indicator:checked {
            image: url(:/icons/radiobutton_checked.png);
        }
        
        QPushButton {
            background-color: #2d2d2d;
            border: 1px solid #444;
            padding: 5px 10px;
        }
        
        QPushButton:hover {
            background-color: #3a3a3a;
        }
        
        QPushButton:pressed {
            background-color: #1d1d1d;
        }
        
        QPushButton:disabled {
            background-color: #1d1d1d;
            color: #666;
            border: 1px solid #333;
        }
        
        QMenu {
            background-color: #2d2d2d;
            border: 1px solid #444;
        }
        
        QMenu::item {
            padding: 5px 20px 5px 20px;
        }
        
        QMenu::item:selected {
            background-color: #2a82da;
        }
        
        QMenuBar {
            background-color: #2d2d2d;
        }
        
        QMenuBar::item {
            padding: 5px 10px;
            background: transparent;
        }
        
        QMenuBar::item:selected {
            background-color: #3a3a3a;
        }
        
        QMenuBar::item:pressed {
            background-color: #2a82da;
        }
        
        QScrollBar:vertical {
            border: none;
            background: #2d2d2d;
            width: 12px;
            margin: 0px;
        }
        
        QScrollBar::handle:vertical {
            background: #3a3a3a;
            min-height: 20px;
            border-radius: 2px;
        }
        
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0px;
        }
        
        QScrollBar::up-arrow:vertical, QScrollBar::down-arrow:vertical {
            background: none;
        }
        
        QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
            background: none;
        }
        
        QScrollBar:horizontal {
            border: none;
            background: #2d2d2d;
            height: 12px;
            margin: 0px;
        }
        
        QScrollBar::handle:horizontal {
            background: #3a3a3a;
            min-width: 20px;
            border-radius: 2px;
        }
        
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
            width: 0px;
        }
        
        QScrollBar::left-arrow:horizontal, QScrollBar::right-arrow:horizontal {
            background: none;
        }
        
        QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {
            background: none;
        }
    """)