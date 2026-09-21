import { z } from 'zod';

// Zod 4 pri pravljenju semi pokusava `new Function("")` da bi kompajlirao brze provere. Politika
// zastite pregledaca (CSP bez 'unsafe-eval') to zabranjuje, pa pregledac prijavi povredu iako se
// koristi sporiji put. Ovaj modul se zato uvozi PRVI u klijentu, pre nego sto se ijedna sema napravi.
z.config({ jitless: true });
