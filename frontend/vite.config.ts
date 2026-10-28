import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import { readFileSync } from 'node:fs';
export default defineConfig({define:{__APP_VERSION__:JSON.stringify(readFileSync(new URL('../VERSION',import.meta.url),'utf8').trim())},plugins:[react()],server:{host:'127.0.0.1',port:5177,strictPort:true,proxy:{'/api':{target:'http://127.0.0.1:8007',changeOrigin:false}}},test:{environment:'jsdom',setupFiles:['./src/test/setup.ts'],css:true,clearMocks:true,restoreMocks:true}});
