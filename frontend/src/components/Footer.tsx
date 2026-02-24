import Link from 'next/link';

export function Footer() {
  return (
    <footer className="border-t bg-background">
      <div className="container mx-auto max-w-7xl py-12 px-4 md:px-6">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
          <div>
            <h3 className="font-semibold mb-4">Marketplace</h3>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li><Link href="/equipment" className="hover:text-foreground">Browse Equipment</Link></li>
              <li><Link href="/equipment/new" className="hover:text-foreground">List Your Gear</Link></li>
              <li><Link href="/categories" className="hover:text-foreground">Categories</Link></li>
            </ul>
          </div>
          <div>
            <h3 className="font-semibold mb-4">Company</h3>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li><Link href="/about" className="hover:text-foreground">About Us</Link></li>
              <li><Link href="/contact" className="hover:text-foreground">Contact</Link></li>
              <li><Link href="/careers" className="hover:text-foreground">Careers</Link></li>
            </ul>
          </div>
          <div>
            <h3 className="font-semibold mb-4">Legal</h3>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li><Link href="/terms" className="hover:text-foreground">Terms of Service</Link></li>
              <li><Link href="/privacy" className="hover:text-foreground">Privacy Policy</Link></li>
              <li><Link href="/cookies" className="hover:text-foreground">Cookie Policy</Link></li>
            </ul>
          </div>
          <div>
            <h3 className="font-semibold mb-4">Connect</h3>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li><a href="#" className="hover:text-foreground">Twitter</a></li>
              <li><a href="#" className="hover:text-foreground">Instagram</a></li>
              <li><a href="#" className="hover:text-foreground">Discord</a></li>
            </ul>
          </div>
        </div>
        <div className="mt-12 pt-8 border-t text-center text-sm text-muted-foreground">
          <p>&copy; {new Date().getFullYear()} Rust Backend UI. All rights reserved.</p>
        </div>
      </div>
    </footer>
  );
}
