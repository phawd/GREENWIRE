#!/usr/bin/env python3
"""
GREENWIRE Menu System
Configuration-driven menu system that consolidates and streamlines all menu operations
"""

import os
from typing import Any, Callable, Dict, List, Optional, Union  # noqa: F401
from dataclasses import dataclass, field
from enum import Enum
from core.config import get_config
from core.logging_system import get_logger, handle_errors
from core.imports import ModuleManager

# Prefer centralized MENU_ACTIONS registry for handlers to avoid fragile
# attribute introspection/import patterns. This ensures every menu entry maps
# cleanly to an implementation in one place (menu_handlers.py).
try:  # Local import relative to GREENWIRE root
    from menu_handlers import MENU_ACTIONS, handle_menu_action
except ImportError:  # Fallback if path issues arise – registry features disabled
    MENU_ACTIONS = {}
    def handle_menu_action(action_name: str, *args, **kwargs):  # type: ignore
        raise RuntimeError("MENU_ACTIONS registry unavailable – menu_handlers import failed")

# Menu item types
class MenuItemType(Enum):
    MENU = "menu"
    ACTION = "action" 
    SEPARATOR = "separator"
    SUBMENU = "submenu"

@dataclass
class MenuItem:
    """Configuration-driven menu item."""
    id: str
    title: str
    item_type: MenuItemType
    emoji: str = ""
    description: str = ""
    action: Optional[Callable] = None
    handler_module: Optional[str] = None
    handler_function: Optional[str] = None
    requirements: List[str] = field(default_factory=list)
    enabled: bool = True
    visible: bool = True
    children: List['MenuItem'] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

class MenuSystem:
    """Configuration-driven menu system."""
    
    def __init__(self):
        self.config = get_config()
        self.logger = get_logger()
        self.import_manager = ModuleManager()
        self.menus = {}
        self.current_menu = None
        
        # Load menu configurations
        self._load_menu_definitions()
        
    def _load_menu_definitions(self):
        """Load menu definitions from configuration."""
        # Main menu structure from config
        main_menu_config = self.config.menu.structure
        
        for menu_key, menu_def in main_menu_config.items():
            menu_items = self._build_menu_items(menu_def.get('items', []))
            self.menus[menu_key] = {
                'title': menu_def.get('title', menu_key.title()),
                'description': menu_def.get('description', ''),
                'items': menu_items,
                'enabled': menu_def.get('enabled', True)
            }
    
    def _build_menu_items(self, items_config: List[Dict]) -> List[MenuItem]:
        """Build MenuItem objects from configuration."""
        items = []
        
        for item_config in items_config:
            if item_config.get('type') == 'separator':
                items.append(MenuItem(
                    id=f"sep_{len(items)}",
                    title="---",
                    item_type=MenuItemType.SEPARATOR
                ))
                continue
            
            # Build regular menu item
            item = MenuItem(
                id=item_config['id'],
                title=item_config['title'],
                item_type=MenuItemType(item_config.get('type', 'action')),
                emoji=item_config.get('emoji', ''),
                description=item_config.get('description', ''),
                handler_module=item_config.get('handler_module'),
                handler_function=item_config.get('handler_function'),
                requirements=item_config.get('requirements', []),
                enabled=item_config.get('enabled', True),
                visible=item_config.get('visible', True),
                metadata=item_config.get('metadata', {})
            )
            
            # Build children for submenus
            if item.item_type == MenuItemType.SUBMENU and 'children' in item_config:
                item.children = self._build_menu_items(item_config['children'])
            
            items.append(item)
        
        return items
    
    @handle_errors("Menu display", return_on_error=None)
    def display_menu(self, menu_key: str = 'main', show_header: bool = True) -> Optional[str]:
        """Display a menu and return the selected option."""
        if menu_key not in self.menus:
            self.logger.error(f"Menu '{menu_key}' not found", "MENU")
            return None
        
        menu_config = self.menus[menu_key]
        if not menu_config['enabled']:
            self.logger.error(f"Menu '{menu_key}' is disabled", "MENU")
            return None
        
        self.current_menu = menu_key
        
        if show_header:
            self._display_menu_header(menu_config['title'], menu_config.get('description'))
        
        # Filter visible and enabled items
        visible_items = [item for item in menu_config['items'] if item.visible and self._check_item_requirements(item)]
        
        if not visible_items:
            print(f"🚫 No available options in {menu_config['title']}")
            return None
        
        # Display menu items
        print(f"\n📋 {menu_config['title']}")
        print("=" * (len(menu_config['title']) + 4))
        
        valid_choices = []
        for i, item in enumerate(visible_items, 1):
            if item.item_type == MenuItemType.SEPARATOR:
                print("   " + "-" * 50)
                continue
            
            # Format menu item display
            status_icon = "🟢" if item.enabled else "🔴"
            item_display = f"{i:2d}) {status_icon} {item.emoji} {item.title}"
            
            if item.description:
                item_display += f" - {item.description}"
            
            print(item_display)
            
            if item.enabled:
                valid_choices.append((str(i), item))
        
        # Add common options
        print(f"\n{len(visible_items) + 1:2d}) 🔄 Refresh menu")
        print(f"{len(visible_items) + 2:2d}) 🏠 Back to main menu")
        print(f"{len(visible_items) + 3:2d}) 🚪 Exit")
        
        valid_choices.extend([
            (str(len(visible_items) + 1), 'refresh'),
            (str(len(visible_items) + 2), 'main'),
            (str(len(visible_items) + 3), 'exit')
        ])
        
        # Get user selection
        while True:
            try:
                choice = input(f"\n🎯 Select option (1-{len(visible_items) + 3}): ").strip()
                
                # Handle special choices
                if choice in ['exit', 'quit', 'q']:
                    return 'exit'
                elif choice in ['main', 'home', 'm']:
                    return 'main'
                elif choice in ['refresh', 'r']:
                    return 'refresh'
                
                # Find matching choice
                for valid_choice, item in valid_choices:
                    if choice == valid_choice:
                        if isinstance(item, MenuItem):
                            return self._handle_menu_item(item)
                        else:
                            return item
                
                print("❌ Invalid choice. Please try again.")
                
            except KeyboardInterrupt:
                print("\n\n🚪 Exiting...")
                return 'exit'
            except Exception as e:
                self.logger.error(f"Menu selection error: {e}", "MENU")
                print("❌ Selection error. Please try again.")
    
    def _display_menu_header(self, title: str, description: str = ""):
        """Display standardized menu header."""
        os.system('cls' if os.name == 'nt' else 'clear')
        
        # GREENWIRE header
        print("🟢" * 60)
        print("🟢" + " " * 18 + "GREENWIRE v3.0" + " " * 18 + "🟢")
        print("🟢" + " " * 10 + "Advanced Payment Card Security Suite" + " " * 10 + "🟢")
        print("🟢" * 60)
        
        if title:
            print(f"\n📱 Current Section: {title}")
            if description:
                print(f"ℹ️  {description}")
        
        # System status
        print(f"\n🔧 Configuration: {self.config.app.environment}")
        print(f"📝 Logging Level: {self.config.logging.level}")
        print(f"🔗 NFC Hardware: {'✅' if self.config.nfc.use_hardware else '❌'}")
        print(f"📱 Android Support: {'✅' if self.config.nfc.use_android else '❌'}")
        
    def _check_item_requirements(self, item: MenuItem) -> bool:
        """Check if menu item requirements are met."""
        if not item.requirements:
            return True
        
        for requirement in item.requirements:
            if requirement == "adb" and not self._check_adb_available():
                return False
            elif requirement == "nfc_hardware" and not self.config.nfc.use_hardware:
                return False
            elif requirement == "android" and not self.config.nfc.use_android:
                return False
            elif requirement == "root" and not self._check_root_available():
                return False
            # Add more requirement checks as needed
        
        return True
    
    def _check_adb_available(self) -> bool:
        """Check if ADB is available."""
        import subprocess
        try:
            result = subprocess.run(['adb', 'version'], capture_output=True, timeout=3)
            return result.returncode == 0
        except:
            return False
    
    def _check_root_available(self) -> bool:
        """Check if root privileges are available."""
        return os.geteuid() == 0 if hasattr(os, 'geteuid') else False
    
    @handle_errors("Menu item handling", return_on_error=None)
    def _handle_menu_item(self, item: MenuItem) -> Optional[str]:
        """Handle menu item selection."""
        if not item.enabled:
            print(f"❌ {item.title} is currently disabled")
            input("Press Enter to continue...")
            return 'refresh'
        
        # Handle submenu
        if item.item_type == MenuItemType.SUBMENU:
            return self._handle_submenu(item)
        
        # Handle action item
        if item.item_type == MenuItemType.ACTION:
            return self._execute_menu_action(item)
        
        return None
    
    def _handle_submenu(self, item: MenuItem) -> Optional[str]:
        """Handle submenu navigation."""
        # Create temporary submenu
        submenu_key = f"submenu_{item.id}"
        self.menus[submenu_key] = {
            'title': item.title,
            'description': item.description,
            'items': item.children,
            'enabled': True
        }
        
        # Display submenu
        result = self.display_menu(submenu_key)
        
        # Clean up temporary submenu
        if submenu_key in self.menus:
            del self.menus[submenu_key]
        
        return result
    
    @handle_errors("Menu action execution", return_on_error='refresh')
    def _execute_menu_action(self, item: MenuItem) -> str:
        """Execute menu action."""
        self.logger.info(f"Executing menu action: {item.title}", "MENU_ACTION")
        
        try:
            # 1. Central registry resolution (preferred): try handler_function then id
            # Handler function name explicitly provided
            if item.handler_function and item.handler_function in MENU_ACTIONS:
                result = handle_menu_action(item.handler_function)
                return 'refresh' if result is None else result

            # Fall back to item id if it directly maps to a registered action
            if item.id in MENU_ACTIONS:
                result = handle_menu_action(item.id)
                return 'refresh' if result is None else result

            # If direct action callable is provided
            if item.action:
                result = item.action()
                return 'refresh' if result is None else result
            
            # If handler module/function is specified
            if item.handler_module and item.handler_function:
                handler = self.import_manager.get_function(item.handler_module, item.handler_function)
                if handler:
                    result = handler()
                    return 'refresh' if result is None else result
                else:
                    print(f"❌ Handler not found via dynamic import: {item.handler_module}.{item.handler_function}")
                    # Provide helpful diagnostics listing nearby registry matches
                    if MENU_ACTIONS:
                        print("🔍 Available registered actions (subset):")
                        sample = list(MENU_ACTIONS.keys())[:15]
                        for name in sample:
                            print(f"   • {name}")
            
            # Fallback - print action info
            print(f"🔧 Action: {item.title}")
            if item.description:
                print(f"📝 Description: {item.description}")
            
            print("⚠️  This action is not yet implemented.")
            input("Press Enter to continue...")
            
        except Exception as e:
            self.logger.error(f"Menu action failed: {e}", "MENU_ACTION")
            print(f"❌ Action failed: {e}")
            input("Press Enter to continue...")
        
        return 'refresh'
    
    def run_main_loop(self):
        """Run the main menu loop."""
        current_menu = 'main'
        
        while True:
            try:
                result = self.display_menu(current_menu)
                
                if result == 'exit':
                    print("👋 Goodbye!")
                    break
                elif result == 'main':
                    current_menu = 'main'
                elif result == 'refresh':
                    continue  # Refresh current menu
                elif result and result in self.menus:
                    current_menu = result
                elif result:
                    # Handle other menu navigation results
                    print(f"🔄 Navigating to: {result}")
                    current_menu = result if result in self.menus else 'main'
                
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye!")
                break
            except Exception as e:
                self.logger.error(f"Menu loop error: {e}", "MENU_LOOP")
                print(f"❌ Menu error: {e}")
                input("Press Enter to continue...")
                current_menu = 'main'

# Global menu system instance
_menu_system = None

def get_menu_system() -> MenuSystem:
    """Get the global menu system instance."""
    global _menu_system
    if _menu_system is None:
        _menu_system = MenuSystem()
    return _menu_system