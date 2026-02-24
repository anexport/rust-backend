export const dynamic = 'force-dynamic';
import { fetchServer } from '@/lib/api';
import { Card, CardContent, CardFooter, CardHeader, CardTitle } from '@/components/ui/card';
import Link from 'next/link';

interface Category {
  id: string;
  name: string;
}

interface EquipmentItem {
  id: string;
  title: string;
  description: string;
  daily_rate: number;
  photos: { photo_url: string }[];
}

export default async function EquipmentPage({ searchParams }: { searchParams: Promise<{ category_id?: string }> }) {
  const { category_id } = await searchParams;
  const categoriesRes = await fetchServer('/api/categories');
  const categories: Category[] = categoriesRes.ok ? await categoriesRes.json() : [];

  const query = category_id ? `?category_id=${category_id}` : '';
  const equipmentRes = await fetchServer(`/api/equipment${query}`);
  const equipmentData = equipmentRes.ok ? await equipmentRes.json() : { items: [] as EquipmentItem[] };

  return (
    <main className="container mx-auto py-10 px-4">
      <div className="flex flex-col md:flex-row gap-8">
        <aside className="w-full md:w-64 space-y-4">
          <h2 className="text-xl font-bold">Categories</h2>
          <nav className="flex flex-col space-y-2">
            <Link href="/equipment" className={!category_id ? "font-bold text-primary" : "text-muted-foreground hover:text-foreground"}>All</Link>
            {categories.map((c) => (
              <Link 
                key={c.id} 
                href={`/equipment?category_id=${c.id}`}
                className={category_id === c.id ? "font-bold text-primary" : "text-muted-foreground hover:text-foreground"}
              >
                {c.name}
              </Link>
            ))}
          </nav>
        </aside>
        
        <div className="flex-1">
          <div className="flex justify-between items-center mb-6">
            <h1 className="text-3xl font-bold">Equipment</h1>
            <Link href="/equipment/new" className="bg-primary text-primary-foreground px-4 py-2 rounded-md hover:bg-primary/90 text-sm font-medium">
              List Item
            </Link>
          </div>
          
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
            {equipmentData.items.map((item: EquipmentItem) => (
              <Card key={item.id} className="flex flex-col">
                <CardHeader>
                  <CardTitle className="text-lg line-clamp-1">{item.title}</CardTitle>
                </CardHeader>
                <CardContent className="flex-1">
                  {item.photos && item.photos.length > 0 ? (
                    <img 
                      src={item.photos[0].photo_url} 
                      alt={item.title} 
                      className="w-full h-48 object-cover rounded-md mb-4" 
                    />
                  ) : (
                    <div className="w-full h-48 bg-muted rounded-md mb-4 flex items-center justify-center text-muted-foreground">
                      No image
                    </div>
                  )}
                  <p className="text-sm text-muted-foreground line-clamp-2">{item.description}</p>
                </CardContent>
                <CardFooter className="flex justify-between items-center mt-auto">
                  <span className="font-bold">${item.daily_rate}/day</span>
                  <Link href={`/equipment/${item.id}`} className="text-sm text-primary hover:underline">
                    View Details
                  </Link>
                </CardFooter>
              </Card>
            ))}
            {equipmentData.items.length === 0 && (
              <div className="col-span-full text-center py-10 text-muted-foreground">
                No equipment found matching your criteria.
              </div>
            )}
          </div>
        </div>
      </div>
    </main>
  );
}
