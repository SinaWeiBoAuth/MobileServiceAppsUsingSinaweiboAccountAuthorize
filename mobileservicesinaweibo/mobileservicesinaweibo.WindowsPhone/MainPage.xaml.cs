using Windows.UI.Xaml.Controls;

namespace mobileservicesinaweibo
{
    public sealed partial class MainPage : Page
    {
        private async void ButtonLogin_Click(object sender, Windows.UI.Xaml.RoutedEventArgs e)
        {
            await AuthenticateAsync();
        }
    }
}
