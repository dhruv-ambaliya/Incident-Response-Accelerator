import tkinter as tk
from tkinter import messagebox

# Import your functionalities (replace with actual imports)
import brand_monit
import config
import dns_option
import file_sandbox
import phishing_analysis
import reputation_check
import sanitize
import url_decoding


def handle_error(error_message):
    """Displays an error message to the user."""
    messagebox.showerror("Error", error_message)


def exit_application():
    """Exits the application."""
    root.quit()


def navigate_to(function):
    """Calls the selected functionality."""
    try:
        function()
    except Exception as e:
        handle_error(f"Error: {e}")


def open_sub_menu(menu_name, sub_menu):
    """Opens the selected sub-menu within the main menu."""
    for item in menu_name.children.values():
        item.config(state=tk.DISABLED)
    for item in sub_menu.children.values():
        item.config(state=tk.NORMAL)


def close_sub_menu(menu_name):
    """Closes the opened sub-menu and restores the main menu."""
    for item in menu_name.children.values():
        item.config(state=tk.NORMAL)


def main_menu():
    """Creates the main menu with top-level options."""
    global root

    root = tk.Tk()
    root.title("Security Event Analysis Tool")

    # Menu bar
    menu_bar = tk.Menu(root)
    root.config(menu=menu_bar)

    # Option 1 - Reputation Check
    reputation_menu = tk.Menu(menu_bar, tearoff=False)
    menu_bar.add_cascade(label="Reputation/Blocklist Check", menu=reputation_menu)
    reputation_menu.add_command(label="Check IP", command=lambda: navigate_to(reputation_check.input_validate))
    reputation_menu.add_command(label="Check Domain", command=lambda: navigate_to(reputation_check.input_validate))  # Replace with domain check functionality
    reputation_menu.add_command(label="Check URL", command=lambda: navigate_to(reputation_check.input_validate))  # Replace with URL check functionality
    reputation_menu.add_command(label="Check Hash", command=lambda: navigate_to(reputation_check.input_validate))  # Replace with hash check functionality

    # Option 2 - DNS/WHOIS
    dns_menu = tk.Menu(menu_bar, tearoff=False)
    menu_bar.add_cascade(label="DNS/WHOIS Lookup", menu=dns_menu)
    dns_menu.add_command(label="DNS Lookup", command=lambda: navigate_to(dns_option.dnsMenu))
    dns_menu.add_command(label="WHOIS Lookup", command=lambda: navigate_to(dns_option.whoisMenu))  # Replace with WHOIS functionality

    # Option 3 - Email Security
    email_menu = tk.Menu(menu_bar, tearoff=False)
    menu_bar.add_cascade(label="Email Security", menu=email_menu)
    email_menu.add_command(label="Phishing Analysis", command=lambda: navigate_to(phishing_analysis.menu))

    # Option 4 - URL Decoding
    url_menu = tk.Menu(menu_bar, tearoff=False)
    menu_bar.add_cascade(label="URL Decoding", menu=url_menu)
    url_menu.add_command(label="Decode URL", command=lambda: navigate_to(url_decoding.menu))

    # Option 5 - File Sandbox
    file_menu = tk.Menu(menu_bar, tearoff=False)
    menu_bar.add_cascade(label="File Sandbox", menu=file_menu)
    file_menu.add_command(label="Upload File", command=lambda: navigate_to(file_sandbox.file_sandbox))

    # Option 6 - Sanitization
    sanitize_menu = tk.Menu(menu_bar, tearoff=False)
    menu_bar.add_cascade(label="Sanitization", menu=sanitize_menu)
    sanitize_menu.add_command(label="Sanitize IOCs")
    # Option 7 - Brand Monitoring (Sub-menu)
    brand_monitoring_menu = tk.Menu(menu_bar, tearoff=False)
    menu_bar.add_cascade(label="Brand Monitoring", menu=brand_monitoring_menu)

    sub_menu1 = tk.Menu(brand_monitoring_menu, tearoff=False)
    brand_monitoring_menu.add_cascade(label="Set Up Monitoring", menu=sub_menu1)
    sub_menu1.add_command(label="Configure Brand Terms", command=lambda: navigate_to(brand_monit.configure_terms))  # Replace with brand term configuration

    sub_menu2 = tk.Menu(brand_monitoring_menu, tearoff=False)
    brand_monitoring_menu.add_cascade(label="View Reports", menu=sub_menu2)
    sub_menu2.add_command(label="Latest Monitoring Results", command=lambda: navigate_to(brand_monit.view_reports))  # Replace with report viewing functionality

    # Option 8 - Help & Configuration
    config_menu = tk.Menu(menu_bar, tearoff=False)
    menu_bar.add_cascade(label="Help & Configuration", menu=config_menu)
    config_menu.add_command(label="Help & Documentation", command=lambda: navigate_to(config.show_help))  # Replace with help documentation
    config_menu.add_command(label="API Key Configuration", command=lambda: navigate_to(config.menu))

    # Option 0 - Exit
    exit_menu = tk.Menu(menu_bar, tearoff=False)
    menu_bar.add_cascade(label="Exit", menu=exit_menu)
    exit_menu.add_command(label="Exit Tool", command=exit_application)

    # Initially disable sub-menus
    for menu in [sub_menu1, sub_menu2]:
        for item in menu.children.values():
            item.config(state=tk.DISABLED)

    root.mainloop()


if __name__ == "__main__":
    main_menu()
