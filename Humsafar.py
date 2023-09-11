from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.progressbar import ProgressBar
from kivy.uix.WebView import WebView

class BrowserWindow(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orientation = 'vertical'

        # Create a WebView for the browser
        self.browser = WebView(url="https://duckduckgo.com")
        self.add_widget(self.browser)

        # Create an address bar
        self.address_bar = TextInput(hint_text="Enter URL or search")
        self.add_widget(self.address_bar)

        # Create a navigation toolbar
        nav_toolbar = BoxLayout()
        self.add_widget(nav_toolbar)

        # Create a "Go" button
        go_button = Button(text="Go/Search")
        go_button.bind(on_press=self.navigate_or_search)
        nav_toolbar.add_widget(go_button)

        # Create a progress bar
        self.progress_bar = ProgressBar(max=100)
        self.progress_bar.opacity = 0  # Initially hidden
        nav_toolbar.add_widget(self.progress_bar)

        # Create reload and abort buttons
        reload_button = Button(text="Reload")
        reload_button.bind(on_press=self.reload_page)
        nav_toolbar.add_widget(reload_button)

        abort_button = Button(text="Abort")
        abort_button.bind(on_press=self.abort_loading)
        nav_toolbar.add_widget(abort_button)

        # Create back and forward buttons
        back_button = Button(text="Back")
        back_button.bind(on_press=self.browser.go_back)
        nav_toolbar.add_widget(back_button)

        forward_button = Button(text="Forward")
        forward_button.bind(on_press=self.browser.go_forward)
        nav_toolbar.add_widget(forward_button)

    def navigate_or_search(self, instance):
        query = self.address_bar.text
        if not query.startswith(("http://", "https://")):
            # If it's not a URL, perform a DuckDuckGo search
            search_url = f"https://duckduckgo.com/?q={query.replace(' ', '+')}"
            self.browser.url = search_url
        else:
            # If it's a URL, navigate to the entered URL
            self.browser.url = query

    def reload_page(self, instance):
        self.browser.reload()

    def abort_loading(self, instance):
        self.browser.stop_loading()

    def on_progress(self, instance, value):
        # Update the progress bar
        self.progress_bar.value = value
        if value == 100:
            # Hide the progress bar when loading is finished
            self.progress_bar.opacity = 0
        else:
            # Show the progress bar when loading starts
            self.progress_bar.opacity = 1

class BrowserApp(App):
    def build(self):
        return BrowserWindow()

if __name__ == "__main__":
    BrowserApp().run()
