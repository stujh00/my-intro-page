const fs=require('node:fs');const esbuild=require('esbuild');
fs.mkdirSync('public',{recursive:true});
for(const file of ['index.html','jihun.jpg','linkedin-profile.png','playlist.png'])fs.copyFileSync(file,'public/'+file);
esbuild.buildSync({entryPoints:['client.js'],bundle:true,format:'iife',outfile:'public/workshop.js',minify:true,platform:'browser'});
