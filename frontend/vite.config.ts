import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
export default defineConfig({plugins:[react()],server:{host:'127.0.0.1',port:5177,strictPort:true,proxy:{'/api':{target:'http://127.0.0.1:8007',changeOrigin:false}}},test:{environment:'jsdom',setupFiles:['./src/test/setup.ts'],css:true,clearMocks:true,restoreMocks:true}});
