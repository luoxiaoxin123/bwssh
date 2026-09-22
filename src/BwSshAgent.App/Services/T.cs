using BwSshAgent.Core;
using Microsoft.UI.Xaml.Markup;

namespace BwSshAgent.App;

/// <summary>XAML text in both languages: {l:T Zh='登录', En='Sign in'}.</summary>
[MarkupExtensionReturnType(ReturnType = typeof(string))]
public sealed partial class T : MarkupExtension
{
    public string Zh { get; set; } = "";
    public string En { get; set; } = "";

    protected override object ProvideValue() => L.T(Zh, En);
}
