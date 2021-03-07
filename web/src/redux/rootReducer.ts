import { combineReducers } from "@reduxjs/toolkit";

//Reducers
import dataReducer from './reducers/data';

const rootReducer = combineReducers({
    data: dataReducer
});

export type RootState = ReturnType<typeof rootReducer>;
export default rootReducer;