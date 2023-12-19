import {Route, BrowserRouter as Router, Routes} from "react-router-dom";
import {Login} from "./components/Login";
import {Register} from "./components/Register";

function App() {
  return (
      <>
      <Router>
          <Routes>
              <Route path='/' element={<Login/>}/>
              <Route path='/login' element={<Login/>}/>
              <Route path='/register' element={<Register/>}/>
              <Route path='*' element={<div>error 404</div>}/>
          </Routes>
      </Router>
      </>
  );
}

export default App;
