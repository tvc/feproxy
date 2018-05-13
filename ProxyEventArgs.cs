using System;

namespace FEProxy {
	class ProxyEventArgs : EventArgs {
		Proxy _proxy;

		public Proxy Proxy => _proxy;

		public ProxyEventArgs( Proxy proxy ) {
			_proxy = proxy;
		}
	}
}